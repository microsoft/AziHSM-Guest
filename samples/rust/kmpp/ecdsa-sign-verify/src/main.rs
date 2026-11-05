// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! KMPP × AziHSM — ECDSA sign -> verify.
//!
//! Usage: `ecdsa-sign-verify [curve]`, where `curve` is `p256` (default),
//! `p384`, or `p521`. The matching embedded EC test key is imported into KMPP;
//! signing runs inside AziHSM and the signature is verified independently with
//! the public key.

fn main() {
    std::process::exit(run());
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    let arg = std::env::args().nth(1);
    if matches!(arg.as_deref(), Some("-h") | Some("--help")) {
        println!("Usage: ecdsa-sign-verify [curve]   # curve: p256 (default), p384, p521");
        return 0;
    }
    println!("=== KMPP x AziHSM: ECDSA sign -> verify ===");
    match run_inner(arg.as_deref()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Import the selected curve's embedded key, then sign and verify.
#[cfg(target_os = "linux")]
fn run_inner(curve_arg: Option<&str>) -> Result<(), String> {
    use kmpp_sample_common::kmpp;
    use kmpp_sample_common::kmpp::SigScheme;
    use kmpp_sample_common::testkeys;
    use kmpp_sample_common::util::{print_hex, SAMPLE_MESSAGE};

    let (curve_name, curve_key) = testkeys::select_ec(curve_arg)?;

    let ctx = kmpp::ProviderCtx::new()?;

    println!("[step 1] import + load embedded EC {curve_name} test key (SIGN usage)");
    let key_id = kmpp::import_key_der(kmpp::KEYISO_KEY_USAGE_SIGN_FLAG, curve_key)?;
    let pkey = kmpp::load_provider_private_key(&ctx, &key_id)?;
    let pubkey = kmpp::public_from_key(&pkey)?;

    println!("[step 2] sign with private key -> KMPP -> AziHSM (ECDSA / SHA-256)");
    let sig = kmpp::digest_sign_sha256(&pkey, SAMPLE_MESSAGE, SigScheme::Ecdsa)?;
    println!(
        "  signed {} bytes -> {} byte signature (DER)",
        SAMPLE_MESSAGE.len(),
        sig.len()
    );
    print_hex("signature", &sig);

    println!("[step 3] verify with public key");
    if !kmpp::digest_verify_sha256(&pubkey, SAMPLE_MESSAGE, &sig, SigScheme::Ecdsa)? {
        return Err("ECDSA signature failed to verify".to_string());
    }

    println!("\n[PASS] ECDSA {curve_name} sign/verify — signature produced inside AziHSM.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run() -> i32 {
    kmpp_sample_common::util::requires_linux("ecdsa-sign-verify");
    0
}
