// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! KMPP × AziHSM — RSA sign -> verify, for PKCS#1 v1.5 and PSS.
//!
//! Usage: `rsa-sign-verify [size]`, where `size` is `2048` (default), `3072`,
//! or `4096` (`2k`/`3k`/`4k` also accepted). The matching embedded RSA test key
//! is imported into KMPP; signing runs inside AziHSM and each signature is
//! verified independently with the public key.

fn main() {
    std::process::exit(run());
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    let arg = std::env::args().nth(1);
    if matches!(arg.as_deref(), Some("-h") | Some("--help")) {
        println!("Usage: rsa-sign-verify [size]   # size: 2048 (default), 3072, 4096");
        return 0;
    }
    println!("=== KMPP x AziHSM: RSA sign -> verify (PKCS#1 v1.5 + PSS) ===");
    match run_inner(arg.as_deref()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(target_os = "linux")]
fn run_inner(size_arg: Option<&str>) -> Result<(), String> {
    use kmpp_sample_common::kmpp;
    use kmpp_sample_common::kmpp::SigScheme;
    use kmpp_sample_common::testkeys;
    use kmpp_sample_common::util::{print_hex, SAMPLE_MESSAGE};

    let (key_name, key_der) = testkeys::select_rsa(size_arg)?;

    let ctx = kmpp::ProviderCtx::new()?;

    println!("[step 1] import + load embedded {key_name} test key (SIGN usage)");
    let key_id = kmpp::import_key_der(kmpp::KEYISO_KEY_USAGE_SIGN_FLAG, key_der)?;
    let pkey = kmpp::load_provider_private_key(&ctx, &key_id)?;
    let pubkey = kmpp::public_from_key(&pkey)?;

    for scheme in [SigScheme::RsaPkcs1, SigScheme::RsaPss] {
        println!("[sign/verify] {scheme}");
        let sig = kmpp::digest_sign_sha256(&pkey, SAMPLE_MESSAGE, scheme)?;
        println!(
            "  signed {} bytes -> {} byte signature",
            SAMPLE_MESSAGE.len(),
            sig.len()
        );
        print_hex("signature", &sig);

        if !kmpp::digest_verify_sha256(&pubkey, SAMPLE_MESSAGE, &sig, scheme)? {
            return Err(format!("{scheme} signature failed to verify"));
        }
        println!("  verified OK");
    }

    println!(
        "\n[PASS] {key_name} sign/verify (PKCS#1 v1.5 + PSS) — signatures produced inside AziHSM."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run() -> i32 {
    kmpp_sample_common::util::requires_linux("rsa-sign-verify");
    0
}
