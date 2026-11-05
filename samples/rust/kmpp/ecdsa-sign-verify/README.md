# KMPP Sample — ECDSA-SIGN-VERIFY

This sample demonstrates AziHSM through KMPP in the following scenario:

1. Import the **embedded** EC test key for the chosen curve into KMPP → the private key is
   materialized inside AziHSM.
2. Load it back through the KMPP OpenSSL provider as an `EVP_PKEY`.
3. **Sign** a message with the private key inside AziHSM (ECDSA / SHA-256).
4. **Verify** the signature independently with the public key (OpenSSL `default` provider).

The curve is selected at runtime (P-256 / P-384 / P-521), each backed by its own embedded key.

## How to run

> See the top-level [README](../README.md) for prerequisites and the one-time device setup.

```bash
# from the samples/rust/kmpp directory:
cargo build --release -p ecdsa-sign-verify

# default curve is P-256:
sudo ./target/release/ecdsa-sign-verify

# or pick a curve — p256 | p384 | p521:
sudo ./target/release/ecdsa-sign-verify p384
sudo ./target/release/ecdsa-sign-verify p521
```

The optional argument selects the curve (default `p256`); a **SIGN**-usage flag is applied on
import. Run with `--help` for the usage line.

Expected output ends with (curve name reflects the argument):

```
[PASS] ECDSA P-256 sign/verify — signature produced inside AziHSM.
```
