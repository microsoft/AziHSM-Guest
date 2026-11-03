# KMPP Sample — RSA-ENCRYPT-DECRYPT

This sample demonstrates AziHSM through KMPP in the following scenario:

1. Import the **embedded** RSA test key for the chosen size into KMPP → the private key is
   materialized inside AziHSM.
2. Load it back through the KMPP OpenSSL provider as an `EVP_PKEY`.
3. RSA-OAEP **encrypt** a message with the public key — this runs **in-process on the CPU** (a
   public-key operation needs no private key, so it is *not* offloaded to the AziHSM device).
4. RSA-OAEP **decrypt** the ciphertext with the private key → routed to KMPP → AziHSM.
5. Verify `plaintext == decrypted`.

The private-key operation runs inside the HSM; the app never sees the key. The test keys are
embedded in the source (`common/src/testkeys.rs`), and the key size is selected at runtime
(RSA-2048 / 3072 / 4096).

## How to run

> See the top-level [README](../README.md) for prerequisites and the one-time device setup.

```bash
cargo build --release -p rsa-encrypt-decrypt

# default size is RSA-2048:
sudo env OPENSSL_CONF=/dev/null ./target/release/rsa-encrypt-decrypt

# or pick a size — 2048 | 3072 | 4096 (2k/3k/4k also accepted):
sudo env OPENSSL_CONF=/dev/null ./target/release/rsa-encrypt-decrypt 4096
```

The optional argument selects the key size (default `2048`); RSA-OAEP decrypt uses an
**ENCRYPT**-usage key, applied on import. Run with `--help` for the usage line.

Expected output ends with:

```
[PASS] RSA-OAEP round-trip verified — private-key op ran inside AziHSM.
```

`import ret=1` (or `-1`) is normal — see the top-level README's Constraints.
