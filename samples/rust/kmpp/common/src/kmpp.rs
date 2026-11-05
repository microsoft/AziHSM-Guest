// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Safe wrappers over KMPP + OpenSSL used by the samples.
//!
//! OpenSSL work goes through the maintained `openssl` crate; the only FFI is the
//! thin `libkmpp` shim in [`crate::ffi`] for the `KeyIso_*` client entry points.
//!
//! Flow: [`import_key_der`] (embedded raw key → in-process self-signed PFX →
//! KMPP import → opaque [`KeyId`]) → [`load_provider_private_key`] (KeyID →
//! provider-backed [`openssl::pkey::PKey`]) → one of [`rsa_oaep`],
//! [`digest_sign_sha256`], [`digest_verify_sha256`].

use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;

use foreign_types::ForeignType;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::lib_ctx::LibCtx;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::pkey_ctx::PkeyCtx;
use openssl::provider::Provider;
use openssl::rsa::Padding;
use openssl::sign::RsaPssSaltlen;
use openssl::sign::Signer;
use openssl::sign::Verifier;
use openssl::x509::X509Builder;
use openssl::x509::X509NameBuilder;

use crate::ffi;

/// `KEYISO_KEY_USAGE_SIGN_FLAG` (keyisocert.h) — single "sign" usage.
pub const KEYISO_KEY_USAGE_SIGN_FLAG: c_int = 0x0000_1000;
/// `KEYISO_KEY_USAGE_ENCRYPT_FLAG` (keyisocert.h) — single "encrypt" usage.
pub const KEYISO_KEY_USAGE_ENCRYPT_FLAG: c_int = 0x0000_2000;

/// Password for the throwaway self-signed PFX built by [`import_key_der`].
const IMPORT_PFX_PASSWORD: &str = "sample";

/// Format an OpenSSL error stack as a string.
fn os_err(e: ErrorStack) -> String {
    e.to_string()
}

/// Signature scheme selected per operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigScheme {
    /// RSA PKCS#1 v1.5 (RSA key default padding).
    RsaPkcs1,
    /// RSA-PSS with salt length == hash length (what AziHSM expects).
    RsaPss,
    /// ECDSA (padding is not applicable).
    Ecdsa,
}

impl std::fmt::Display for SigScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SigScheme::RsaPkcs1 => "RSA PKCS#1 v1.5",
            SigScheme::RsaPss => "RSA-PSS",
            SigScheme::Ecdsa => "ECDSA",
        };
        f.write_str(s)
    }
}

// -------------------------------------------------------------------------
// OpenSSL library context + providers.
// -------------------------------------------------------------------------

/// An `OSSL_LIB_CTX` with the `default` and `kmppprovider` providers loaded.
///
/// Field order is load-bearing: Rust drops fields in declaration order, and a
/// `Provider` must be unloaded **before** the `LibCtx` it was loaded into is
/// freed (unloading a provider after its library context is gone is a
/// use-after-free). So the providers are declared first and `lib_ctx` last.
pub struct ProviderCtx {
    _default: Provider,
    _kmpp: Provider,
    lib_ctx: LibCtx,
}

impl ProviderCtx {
    /// Create the context and load both providers.
    pub fn new() -> Result<Self, String> {
        // Surface a friendly libkmpp-not-found error before touching OpenSSL.
        ffi::kmpp()?;

        let lib_ctx =
            LibCtx::new().map_err(|e| format!("OSSL_LIB_CTX_new failed: {}", os_err(e)))?;
        let default = Provider::load(Some(&lib_ctx), "default")
            .map_err(|e| format!("failed to load OpenSSL 'default' provider: {}", os_err(e)))?;
        let kmpp = Provider::load(Some(&lib_ctx), "kmppprovider").map_err(|e| {
            format!(
                "failed to load 'kmppprovider' (install the KMPP OpenSSL provider, or set \
                 OPENSSL_MODULES to the directory that holds kmppprovider.so): {}",
                os_err(e)
            )
        })?;
        Ok(Self {
            _default: default,
            _kmpp: kmpp,
            lib_ctx,
        })
    }
}

// -------------------------------------------------------------------------
// Opaque KeyID (KMPP-owned) + import.
// -------------------------------------------------------------------------

/// Opaque KMPP KeyID (freed with `KeyIso_clear_free_string`).
pub struct KeyId {
    ptr: *mut c_char,
}

impl Drop for KeyId {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        if let Ok(k) = ffi::kmpp() {
            // SAFETY: `ptr` came from KeyIso_import_pfx_to_key_id.
            unsafe { (k.clear_free_string)(self.ptr) };
        }
    }
}

/// Import a raw private key (unencrypted PKCS#8 DER) into KMPP — the way the
/// samples embed their test keys (the KMPP analog of KSP's `wrap_rsa_key`):
/// decode the key, mint a throwaway self-signed certificate over it, package the
/// pair as a PKCS#12, and import that. Returns the opaque KeyID.
pub fn import_key_der(usage_flag: c_int, key_der: &[u8]) -> Result<KeyId, String> {
    let pfx = build_self_signed_pfx(key_der)?;
    import_pfx(usage_flag, &pfx, IMPORT_PFX_PASSWORD)
}

/// Build a PKCS#12 (PFX) DER from a raw private key (DER; PKCS#1 / SEC1 / PKCS#8
/// are all accepted) by minting a self-signed certificate over it (all via the
/// `openssl` crate).
fn build_self_signed_pfx(key_der: &[u8]) -> Result<Vec<u8>, String> {
    let pkey = PKey::private_key_from_der(key_der)
        .map_err(|e| format!("decoding embedded private key (DER) failed: {}", os_err(e)))?;

    let mut name = X509NameBuilder::new().map_err(os_err)?;
    name.append_entry_by_text("CN", "KMPP Sample")
        .map_err(os_err)?;
    let name = name.build();

    let mut builder = X509Builder::new().map_err(os_err)?;
    builder.set_version(2).map_err(os_err)?;
    let serial = BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .map_err(os_err)?;
    builder.set_serial_number(&serial).map_err(os_err)?;
    builder.set_subject_name(&name).map_err(os_err)?;
    builder.set_issuer_name(&name).map_err(os_err)?; // self-signed: issuer == subject
    builder.set_pubkey(&pkey).map_err(os_err)?;
    let not_before = Asn1Time::days_from_now(0).map_err(os_err)?;
    let not_after = Asn1Time::days_from_now(3650).map_err(os_err)?;
    builder.set_not_before(&not_before).map_err(os_err)?;
    builder.set_not_after(&not_after).map_err(os_err)?;
    builder
        .sign(&pkey, MessageDigest::sha256())
        .map_err(os_err)?;
    let cert = builder.build();

    let mut p12 = Pkcs12::builder();
    p12.name("kmpp-sample").pkey(&pkey).cert(&cert);
    let pkcs12 = p12
        .build2(IMPORT_PFX_PASSWORD)
        .map_err(|e| format!("PKCS12 build failed: {}", os_err(e)))?;
    pkcs12
        .to_der()
        .map_err(|e| format!("PKCS12 to_der failed: {}", os_err(e)))
}

/// Import a PFX into KMPP with a single usage flag. The private key is
/// materialized inside AziHSM; only the opaque KeyID comes back.
fn import_pfx(usage_flag: c_int, pfx: &[u8], password: &str) -> Result<KeyId, String> {
    let k = ffi::kmpp()?;
    let pfx_len: c_int = pfx
        .len()
        .try_into()
        .map_err(|_| "PFX is too large for the C ABI (int length)".to_string())?;
    let pw = CString::new(password).map_err(|_| "password contains an interior NUL".to_string())?;

    let mut verify_chain_error: c_int = 0;
    let mut key_id: *mut c_char = std::ptr::null_mut();

    // SAFETY: NULL correlation id is accepted; `pfx` is readable for `pfx_len`;
    // `pw` is a valid C string; the out-params are writable.
    let ret = unsafe {
        (k.import_pfx_to_key_id)(
            std::ptr::null(),
            usage_flag,
            pfx_len,
            pfx.as_ptr(),
            pw.as_ptr(),
            &mut verify_chain_error,
            &mut key_id,
        )
    };

    // 1 = imported + chain OK; -1 = imported, chain warning (KeyID still usable,
    // e.g. self-signed fixtures); 0 = real failure.
    if key_id.is_null() || ret == 0 {
        return Err(format!(
            "KeyIso_import_pfx_to_key_id failed (ret={ret}, verifyChainError={verify_chain_error})"
        ));
    }
    println!("  imported PFX -> KeyID (isolated in AziHSM); import ret={ret}");
    Ok(KeyId { ptr: key_id })
}

/// Load a KeyID through the KMPP provider into a provider-backed private key.
pub fn load_provider_private_key(
    ctx: &ProviderCtx,
    key_id: &KeyId,
) -> Result<PKey<Private>, String> {
    let k = ffi::kmpp()?;
    // SAFETY: `lib_ctx` is live with kmppprovider loaded; `key_id.ptr` is a valid C string.
    let ptr = unsafe { (k.load_provider_private_key)(ctx.lib_ctx.as_ptr(), key_id.ptr) };
    if ptr.is_null() {
        return Err(format!(
            "KeyIso_load_provider_private_key failed: {}",
            ErrorStack::get()
        ));
    }
    // SAFETY: KeyIso returns an owned EVP_PKEY; PKey takes ownership (frees on drop).
    let pkey = unsafe { PKey::<Private>::from_ptr(ptr) };
    println!(
        "  loaded KeyID via KMPP provider -> EVP_PKEY ({} bits)",
        pkey.bits()
    );
    Ok(pkey)
}

/// Derive a plain public key (default provider) from a provider-backed key, for
/// independent signature verification.
pub fn public_from_key(pkey: &PKey<Private>) -> Result<PKey<Public>, String> {
    let der = pkey
        .public_key_to_der()
        .map_err(|e| format!("public_key_to_der failed: {}", os_err(e)))?;
    PKey::public_key_from_der(&der)
        .map_err(|e| format!("public_key_from_der failed: {}", os_err(e)))
}

// -------------------------------------------------------------------------
// Crypto operations (private-key ops route to KMPP -> AziHSM).
// -------------------------------------------------------------------------

/// One RSA-OAEP direction. `encrypt == true` uses the public key (in-process);
/// `false` routes the decrypt to KMPP → AziHSM. The OAEP hash is left at the
/// OpenSSL default (SHA-1) — KMPP's decrypt path is locked to SHA-1.
pub fn rsa_oaep(pkey: &PKey<Private>, encrypt: bool, input: &[u8]) -> Result<Vec<u8>, String> {
    let mut ctx = PkeyCtx::new(pkey).map_err(|e| format!("PkeyCtx::new failed: {}", os_err(e)))?;
    if encrypt {
        ctx.encrypt_init()
    } else {
        ctx.decrypt_init()
    }
    .map_err(|e| format!("RSA op init failed: {}", os_err(e)))?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|e| format!("set OAEP padding failed: {}", os_err(e)))?;

    // Size probe (to == None), then fill.
    let len = if encrypt {
        ctx.encrypt(input, None::<&mut [u8]>)
    } else {
        ctx.decrypt(input, None::<&mut [u8]>)
    }
    .map_err(|e| format!("RSA op size probe failed: {}", os_err(e)))?;

    let mut out = vec![0u8; len];
    let written = if encrypt {
        ctx.encrypt(input, Some(&mut out))
    } else {
        ctx.decrypt(input, Some(&mut out))
    }
    .map_err(|e| format!("RSA op failed: {}", os_err(e)))?;
    out.truncate(written);
    Ok(out)
}

/// Sign `msg` (hashed with SHA-256) using `scheme`, routed to KMPP → AziHSM.
/// The key is object-anchored to `kmppprovider`, so no property query is needed
/// (a mandatory one would wrongly force the digest fetch into KMPP).
pub fn digest_sign_sha256(
    pkey: &PKey<Private>,
    msg: &[u8],
    scheme: SigScheme,
) -> Result<Vec<u8>, String> {
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)
        .map_err(|e| format!("Signer::new failed: {}", os_err(e)))?;
    if scheme == SigScheme::RsaPss {
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| format!("set PSS padding failed: {}", os_err(e)))?;
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| format!("set PSS salt length failed: {}", os_err(e)))?;
    }
    signer
        .update(msg)
        .map_err(|e| format!("signer update failed: {}", os_err(e)))?;
    signer
        .sign_to_vec()
        .map_err(|e| format!("sign failed: {}", os_err(e)))
}

/// Verify `sig` over `msg` with a plain public key (default provider),
/// independently of KMPP. Returns whether the signature is valid.
pub fn digest_verify_sha256(
    pubkey: &PKey<Public>,
    msg: &[u8],
    sig: &[u8],
    scheme: SigScheme,
) -> Result<bool, String> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pubkey)
        .map_err(|e| format!("Verifier::new failed: {}", os_err(e)))?;
    if scheme == SigScheme::RsaPss {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| format!("set PSS padding failed: {}", os_err(e)))?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| format!("set PSS salt length failed: {}", os_err(e)))?;
    }
    verifier
        .update(msg)
        .map_err(|e| format!("verifier update failed: {}", os_err(e)))?;
    verifier
        .verify(sig)
        .map_err(|e| format!("verify failed: {}", os_err(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkeys;

    // Exercises the embedded-key -> self-signed PFX path (decode + cert +
    // PKCS#12) for every embedded key. This needs no device: it validates that
    // each embedded DER parses and packages, catching format mismatches (e.g.
    // PKCS#1 vs PKCS#8) before a device run.
    #[test]
    fn build_pfx_from_embedded_keys() {
        for (name, key) in [
            ("RSA_2048_KEY", testkeys::RSA_2048_KEY),
            ("EC_P256_KEY", testkeys::EC_P256_KEY),
            ("EC_P384_KEY", testkeys::EC_P384_KEY),
            ("EC_P521_KEY", testkeys::EC_P521_KEY),
        ] {
            let pfx = build_self_signed_pfx(key)
                .unwrap_or_else(|e| panic!("build_self_signed_pfx({name}) failed: {e}"));
            assert!(
                pfx.len() > 300,
                "{name}: PFX too short ({} bytes)",
                pfx.len()
            );
            assert_eq!(pfx[0], 0x30, "{name}: PFX is not a DER SEQUENCE");
        }
    }
}
