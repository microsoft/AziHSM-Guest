// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Small print helpers shared by the samples.

/// Message signed / encrypted by the samples.
#[cfg(target_os = "linux")]
pub const SAMPLE_MESSAGE: &[u8] = b"KMPP x AziHSM: hello from the HSM";

/// Message printed by a sample when built for a non-Linux target.
#[cfg(not(target_os = "linux"))]
pub fn requires_linux(sample: &str) {
    println!(
        "{sample}: this sample requires Linux with the KMPP client + AziHSM \
         runtime installed; nothing to do on this platform."
    );
}

/// Print `buf` as uppercase hex under a label, wrapped for readability.
#[cfg(target_os = "linux")]
pub fn print_hex(label: &str, buf: &[u8]) {
    print!("  {label} ({} bytes):\n    ", buf.len());
    for (i, b) in buf.iter().enumerate() {
        print!("{b:02X}");
        if (i + 1) % 32 == 0 && i + 1 != buf.len() {
            print!("\n    ");
        }
    }
    println!();
}
