// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! KMPP × AziHSM — RSA-OAEP encrypt -> decrypt round-trip.
//!
//! Usage: `rsa-encrypt-decrypt [size]`, where `size` is `2048` (default),
//! `3072`, or `4096` (`2k`/`3k`/`4k` also accepted). The matching embedded RSA
//! test key is imported into KMPP (materialized inside AziHSM); the message is
//! encrypted with the public key in-process, decrypted with the private key
//! inside the HSM, and the round-trip is verified.

fn main() {
    std::process::exit(run());
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    let arg = std::env::args().nth(1);
    if matches!(arg.as_deref(), Some("-h") | Some("--help")) {
        println!("Usage: rsa-encrypt-decrypt [size]   # size: 2048 (default), 3072, 4096");
        return 0;
    }
    println!("=== KMPP x AziHSM: RSA-OAEP encrypt -> decrypt ===");
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
    use kmpp_sample_common::testkeys;
    use kmpp_sample_common::util::{print_hex, SAMPLE_MESSAGE};

    let (key_name, key_der) = testkeys::select_rsa(size_arg)?;

    let ctx = kmpp::ProviderCtx::new()?;

    println!("[step 1] import + load embedded {key_name} test key (ENCRYPT usage)");
    let key_id = kmpp::import_key_der(kmpp::KEYISO_KEY_USAGE_ENCRYPT_FLAG, key_der)?;
    let pkey = kmpp::load_provider_private_key(&ctx, &key_id)?;

    println!("[step 2] encrypt with public key (RSA-OAEP)");
    let ct = kmpp::rsa_oaep(&pkey, true, SAMPLE_MESSAGE)?;
    println!(
        "  encrypted {} bytes -> {} bytes ciphertext",
        SAMPLE_MESSAGE.len(),
        ct.len()
    );
    print_hex("ciphertext", &ct);

    println!("[step 3] decrypt with private key -> KMPP -> AziHSM");
    let pt = kmpp::rsa_oaep(&pkey, false, &ct)?;
    println!("  decrypted -> {} bytes", pt.len());

    println!("[step 4] verify round-trip");
    if pt != SAMPLE_MESSAGE {
        return Err("round-trip mismatch: decrypted != original".to_string());
    }

    println!("\n[PASS] RSA-OAEP round-trip verified — private-key op ran inside AziHSM.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run() -> i32 {
    kmpp_sample_common::util::requires_linux("rsa-encrypt-decrypt");
    0
}
