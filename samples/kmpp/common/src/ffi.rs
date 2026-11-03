// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Thin runtime shim for the **KMPP client** (`libkmpp`).
//!
//! Only the three `KeyIso_*` entry points that no crate provides are reached
//! here; everything else (OpenSSL) goes through the `openssl` crate. libkmpp is
//! resolved at runtime with `dlopen`/`dlsym` (soname `libkmpp.so.1`, devel
//! fallback `libkmpp.so`) and loaded with `RTLD_GLOBAL` so the OpenSSL
//! `kmppprovider` can resolve the `KeyIso_*` helpers it borrows from global scope.

#![allow(non_camel_case_types)]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::sync::OnceLock;

// Raw OpenSSL handle types come from openssl-sys so they match the `openssl`
// crate's `ForeignType` pointers exactly.
use openssl_sys::EVP_PKEY;
use openssl_sys::OSSL_LIB_CTX;

// KMPP client C ABI signatures (kmppclient/include/keyisopfxclient.h,
// keyisoclientprov.h, include/keyisomemory.h).
type FnImportPfxToKeyId = unsafe extern "C" fn(
    correlation_id: *const u8, // uuid_t (unsigned char[16]); NULL is accepted.
    keyiso_flags: c_int,
    in_pfx_length: c_int,
    in_pfx_bytes: *const u8,
    password: *const c_char, // optional; NULL if none.
    verify_chain_error: *mut c_int,
    key_id: *mut *mut c_char, // out: opaque KeyID (clear-free with the fn below).
) -> c_int;

type FnLoadProviderPrivateKey = unsafe extern "C" fn(
    libctx: *mut OSSL_LIB_CTX,
    provider_key_id: *const c_char,
) -> *mut EVP_PKEY;

type FnClearFreeString = unsafe extern "C" fn(s: *mut c_char);

/// Resolved libkmpp entry points.
pub struct Kmpp {
    pub import_pfx_to_key_id: FnImportPfxToKeyId,
    pub load_provider_private_key: FnLoadProviderPrivateKey,
    pub clear_free_string: FnClearFreeString,
}

// SAFETY: plain C function pointers into a process-global, resident shared
// object; sharing them across threads is sound.
unsafe impl Sync for Kmpp {}
unsafe impl Send for Kmpp {}

static KMPP: OnceLock<Result<Kmpp, String>> = OnceLock::new();

/// Candidate sonames tried in order: installed runtime soname, then devel symlink.
const KMPP_SONAMES: &[&str] = &["libkmpp.so.1", "libkmpp.so"];

/// Resolve (once) and return the libkmpp entry points.
pub fn kmpp() -> Result<&'static Kmpp, String> {
    match KMPP.get_or_init(load_kmpp) {
        Ok(k) => Ok(k),
        Err(e) => Err(e.clone()),
    }
}

fn load_kmpp() -> Result<Kmpp, String> {
    // RTLD_NOW: resolve symbols eagerly. RTLD_GLOBAL: expose KeyIso_* to kmppprovider.
    let flags = libc::RTLD_NOW | libc::RTLD_GLOBAL;

    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut tried = Vec::new();
    for name in KMPP_SONAMES {
        let c_name = std::ffi::CString::new(*name).expect("soname has no interior NUL");
        // SAFETY: `c_name` is a valid NUL-terminated string.
        let h = unsafe { libc::dlopen(c_name.as_ptr(), flags) };
        if !h.is_null() {
            handle = h;
            break;
        }
        tried.push(name.to_string());
    }
    if handle.is_null() {
        return Err(format!(
            "could not dlopen libkmpp ({}). Install the KMPP client package and \
             ensure it is on the loader search path (a system lib dir or LD_LIBRARY_PATH).",
            tried.join(", ")
        ));
    }

    // SAFETY: `handle` is a live dlopen handle; the transmutes assert each symbol
    // matches the declared C signature.
    unsafe {
        Ok(Kmpp {
            import_pfx_to_key_id: std::mem::transmute::<*mut c_void, FnImportPfxToKeyId>(dlsym(
                handle,
                "KeyIso_import_pfx_to_key_id",
            )?),
            load_provider_private_key: std::mem::transmute::<*mut c_void, FnLoadProviderPrivateKey>(
                dlsym(handle, "KeyIso_load_provider_private_key")?,
            ),
            clear_free_string: std::mem::transmute::<*mut c_void, FnClearFreeString>(dlsym(
                handle,
                "KeyIso_clear_free_string",
            )?),
        })
    }
}

/// Resolve one symbol from an open dlopen handle.
///
/// # Safety
/// `handle` must be a live handle returned by `dlopen`.
unsafe fn dlsym(handle: *mut c_void, name: &str) -> Result<*mut c_void, String> {
    let c_name = std::ffi::CString::new(name).expect("symbol name has no interior NUL");
    // A NULL result is a valid symbol value, so dlerror is the only reliable
    // failure signal — clear it first.
    libc::dlerror();
    let sym = libc::dlsym(handle, c_name.as_ptr());
    let err = libc::dlerror();
    if !err.is_null() {
        let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
        return Err(format!("libkmpp is missing symbol '{name}': {msg}"));
    }
    Ok(sym)
}
