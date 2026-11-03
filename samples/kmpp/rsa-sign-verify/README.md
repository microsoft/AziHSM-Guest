# KMPP Sample — RSA-SIGN-VERIFY

This sample demonstrates AziHSM through KMPP in the following scenario:

1. Import the **embedded** RSA test key for the chosen size into KMPP → the private key is
   materialized inside AziHSM.
2. Load it back through the KMPP OpenSSL provider as an `EVP_PKEY`.
3. **Sign** a message with the private key inside AziHSM — once with **PKCS#1 v1.5**, once with
   **PSS** (salt length == hash length).
4. **Verify** each signature independently with the public key (OpenSSL `default` provider).

Signing is object-anchored to the key's provider (no `provider=` query), so it runs on AziHSM
while the SHA-256 digest resolves from the default provider. The key size is selected at runtime
(RSA-2048 / 3072 / 4096), each backed by its own embedded key.

## How to run

> See the top-level [README](../README.md) for prerequisites and the one-time device setup.

```bash
cargo build --release -p rsa-sign-verify

# default size is RSA-2048:
sudo env OPENSSL_CONF=/dev/null ./target/release/rsa-sign-verify

# or pick a size — 2048 | 3072 | 4096 (2k/3k/4k also accepted):
sudo env OPENSSL_CONF=/dev/null ./target/release/rsa-sign-verify 3072
```

The optional argument selects the key size (default `2048`); a **SIGN**-usage flag is applied on
import. Run with `--help` for the usage line.

Expected output ends with (size reflects the argument):

```
[PASS] RSA-2048 sign/verify (PKCS#1 v1.5 + PSS) — signatures produced inside AziHSM.
```
