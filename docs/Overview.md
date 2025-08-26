# AziHSM Overview

The AziHSM is a Hardware Security Module (HSM) that enables the creation, caching, and usage of cryptography keys within an isolated hardware environment.
Specifically, AziHSM is a physical device that is installed onto the motherboard of Azure host machines.
Cryptographic keys and security assets are cached within the device.
AziHSM has several hardware cryptographic engines that perform encryption, decryption, signing, and other operations.

AziHSM is designed to meet the Federal Information Processing Standards (FIPS) 140-3 Level 3 Security Requirements for Cryptographic Modules.
Cryptographic keys and security assets *never* leave the device, which ensures they are protected while in use, and are isolated from potential adversarial attacks elsewhere on the physical machine.

If your Azure workloads heavily rely on cryptography and have performance intensive workloads, AziHSM provides a secure way to store cryptographic keys for quick and secure retrieval.

## Supported Operations

The following cryptographic operations are supported by AziHSM:

* **AES - Encrypt + Decrypt**
    * AES-CBC 128
    * AES-CBC 192
    * AES-CBC 256
* **RSA**
    * **Decrypt + Sign**
        * RSA 2048 (2k)
        * RSA 3072 (3k)
        * RSA 4096 (4k)
    * **Unwrap**
        * RSA 2048 (2k)
* **ECC**
    * **ECDSA - Sign**
        * ECC P256
        * ECC P384
        * ECC P521
    * **ECDH - Secret Exchange**
        * ECC P256
        * ECC P384
        * ECC P521
* **Key Derivation**
    * KBKDF ("Key Based Key Derivation Function") - refers to the **SP800-108 HMAC in counter mode** KDF, as seen [here](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation) in the NCrypt API documentation.
    * HKDF ("HMAC-based Key Derivation Function") - as defined in [IETF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and referred to in NCrypt by the `BCRYPT_HKDF_ALGORITHM` string.

