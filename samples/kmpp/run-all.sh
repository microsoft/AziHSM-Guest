#!/usr/bin/env bash
# Copyright (C) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Smoke test: build the samples and run all three against KMPP -> AziHSM.
# Each sample uses its embedded test key, so there is nothing to generate.
# Exits non-zero if any sample fails.
#
#   ./run-all.sh
#
# Env knobs:
#   SUDO=              run without sudo (default: sudo — the device is root-only)
#   OPENSSL_CONF       defaults to /dev/null to keep output clean
#   CARGO_TARGET_DIR   honored for both the build and the binary path

# `set -e` aborts on an unchecked failure (notably `cargo build` below, so a
# broken build never falls through to running stale binaries). The per-sample
# `run ... || fail=1` lines are exempt from `-e` (left side of `||`), so all
# three still run and their results aggregate into `fail`.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

SUDO="${SUDO-sudo}"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"
BIN="${CARGO_TARGET_DIR:-target}/release"

echo "== build =="
cargo build --release

run() { # <binary>
    echo
    echo "== $1 =="
    $SUDO env OPENSSL_CONF="$OPENSSL_CONF" "$BIN/$1"
}

fail=0
run rsa-encrypt-decrypt || fail=1
run rsa-sign-verify     || fail=1
run ecdsa-sign-verify   || fail=1

echo
if [[ $fail -eq 0 ]]; then
    echo "ALL SAMPLES PASSED"
else
    echo "ONE OR MORE SAMPLES FAILED" >&2
fi
exit $fail
