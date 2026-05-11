# Crypto Algorithm Support

The following cryptographic operations are supported by AziHSM:

* **AES - Encrypt + Decrypt** (`BCRYPT_AES_ALGORITHM`)
    * **AES-CBC** (`BCRYPT_CHAIN_MODE_CBC`)
        * 128-bit
        * 192-bit
        * 256-bit
    * **AES-GCM** (`BCRYPT_CHAIN_MODE_GCM`)
        * 256-bit
    * **AES-XTS** (`BCRYPT_XTS_AES_ALGORITHM`)
        * 512-bit
* **RSA** (`BCRYPT_RSA_ALGORITHM`)
    * **Decrypt + Sign**
        * RSA 2048 (2k)
        * RSA 3072 (3k)
        * RSA 4096 (4k)
    * **Unwrap**
        * RSA 2048 (2k)
* **ECC**
    * **ECDSA - Sign** (`BCRYPT_ECDSA_ALGORITHM`)
        * ECC P256 (`BCRYPT_ECDSA_P256_ALGORITHM`)
        * ECC P384 (`BCRYPT_ECDSA_P384_ALGORITHM`)
        * ECC P521 (`BCRYPT_ECDSA_P521_ALGORITHM`)
    * **ECDH - Secret Exchange** (`BCRYPT_ECDH_ALGORITHM`)
        * ECC P256 (`BCRYPT_ECDH_P256_ALGORITHM`)
        * ECC P384 (`BCRYPT_ECDH_P384_ALGORITHM`)
        * ECC P521 (`BCRYPT_ECDH_P521_ALGORITHM`)
* **Key Derivation**
    * **HKDF** ("HMAC-based Key Derivation Function") (`BCRYPT_HKDF_ALGORITHM`)
        * As defined in [IETF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and referred to in NCrypt by the `BCRYPT_HKDF_ALGORITHM` string

