#!/usr/bin/env bash
# Copyright (C) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Smoke test: build the C++ samples, run the device-free tests, then run both
# samples against KMPP -> AziHSM for every RSA size. Each sample uses its embedded
# test key, so there is nothing to generate. Exits non-zero if anything fails.
#
#   ./run-all.sh
#
# Env knobs:
#   SUDO=              run without sudo (default: sudo — /dev/azihsm0 needs root or the azihsm group)
#   OPENSSL_CONF       not needed; if set (e.g. /dev/null to rule out a custom openssl.cnf),
#                      it is forwarded to each sample through sudo

# `set -e` aborts on an unchecked failure (notably `make` below, so a broken build never falls
# through to running stale binaries). The per-sample `run ... || fail=1` lines are exempt from
# `-e` (left side of `||`), so every run still happens and results aggregate into `fail`.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

SUDO="${SUDO-sudo}"

echo "== build =="
make

echo
echo "== device-free tests =="
make --no-print-directory check

run() { # <sample> [size]
    echo
    echo "== $* =="
    # sudo resets the environment, so OPENSSL_CONF is forwarded explicitly when it is set.
    if [[ -n "${OPENSSL_CONF:-}" ]]; then
        $SUDO env OPENSSL_CONF="$OPENSSL_CONF" "./$1/bin/$1" "${@:2}"
    else
        $SUDO "./$1/bin/$1" "${@:2}"
    fi
}

fail=0
for size in 2048 3072 4096; do
    run RSA-ENCRYPT-DECRYPT "$size" || fail=1
    run RSA-SIGN-VERIFY     "$size" || fail=1
done

echo
if [[ $fail -eq 0 ]]; then
    echo "ALL SAMPLES PASSED"
else
    echo "ONE OR MORE SAMPLES FAILED" >&2
fi
exit $fail