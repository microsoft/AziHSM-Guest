// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Shared library for the KMPP × AziHSM samples — the Rust analog of
//! the KSP `cpp` samples' `include/` folder.
//!
//! - [`kmpp`] — safe wrappers: provider context, PFX import (from an embedded raw
//!   key), key load, and the crypto helpers, built on the `openssl` crate plus a
//!   thin `libkmpp` FFI shim (`ffi`, private).
//! - [`testkeys`] — the embedded raw test keys (the KSP `RsaKeys.h` analog).
//! - [`util`] — small print helpers.
//!
//! Each sample crate (one folder per scenario) depends on this crate and
//! implements its scenario in `src/main.rs`.

pub mod testkeys;
pub mod util;

#[cfg(target_os = "linux")]
mod ffi;

#[cfg(target_os = "linux")]
pub mod kmpp;
