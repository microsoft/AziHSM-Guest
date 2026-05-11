# AziHSM Sample - ECDH-KDF-AES

This sample demonstrates the AziHSM in the following scenario:

1. Generate two ECDH public/private key pairs. (Each key pair represents a separate party: "Alice" (party 1) and "Bob" (party 2))
2. Perform ECDH key exchange, to exchange public keys between the two parties, and generate a shared secret.
3. Use HKDF to derive the same AES key (using the shared secret) for both parties.
    * HKDF ("HMAC-based Key Derivation Function") is defined in [IETF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and is referred to in NCrypt by the `BCRYPT_HKDF_ALGORITHM` string.
    * The derived AES key can be either AES-CBC or AES-GCM.
4. Perform AES encryption and decryption to verify that the two derived AES keys are identical.
    * AES-CBC or AES-GCM is performed depending on the derived AES key type.

This scenario shows one way to utilize the AziHSM to establish a secure communication channel between two parties.

Even though both parties are represented within the same user-space process in this demonstration, this scenario can be applied to two completely separate/isolated parties to securely communicate with one another.

## How to run

> See top-level [README.md](../README.md) for prerequisites.

```powershell
# (No command-line arguments: derives an AES-GCM key)
.\ECDH-KDF-AES.exe

# Specify "gcm" to derive an AES-GCM key
.\ECDH-KDF-AES.exe gcm

# Specify "cbc" to derive an AES-CBC key
.\ECDH-KDF-AES.exe cbc
```

You should see output similar to this:

<details>
<summary>(Click here)</summary>

```
AziHSM Demonstration: ECDH Generate --> ECDH Exchange --> KDF AES --> AES Enc/Dec
=================================================================================
Keys will be derived using HKDF.
An AES-GCM key will be derived and used for encryption & decryption.
Opened NCrypt Storage Provider handle: 0x8b768740

Step 1: Generate ECDH Key Pairs for Alice and Bob
-------------------------------------------------
Generated Alice's ECDH key pair. Key handle: 0x8b77e730
Generated Bob's ECDH key pair. Key handle: 0x8b77e670

Step 2: Export and Exchange Public Keys
---------------------------------------
Exported Alice's public key: 72 bytes
Exported Bob's public key: 72 bytes

Step 3: Generate Shared Secrets
-------------------------------
Alice generated shared secret. Handle: 0x8b7785d0
Bob generated shared secret. Handle: 0x8b7789b0

Step 4: Derive AES Keys using HKDF
----------------------------------
Set AES key chaining mode to: ChainingModeGCM.
Finalized AES key successfully.
Alice derived AES key. Handle: 0x8b77e330
Set AES key chaining mode to: ChainingModeGCM.
Finalized AES key successfully.
Bob derived AES key. Handle: 0x8b77e4f0

Step 5: Test Encryption and Decryption
--------------------------------------
Original plaintext:
        C09EE67A237FC22C24E2A66413768C9DF935A9CEFF83AD03B32DFE314E77885FB62357DA4DD5A3B62558B3F8BA8E2A75323D0EDD828D525BFE204907CC37A46D
Ciphertext:
        27F9F8FD764B1B001AF79568E4D552FBE4DBACACE47FEC27D2B577DB6B7DFF3F6B0D3565D34A77D220FB954E90F266630D8A5D95CB828AD3D1DEDA33A8511585
Generated IV:
        E0BA7A2A581BD3B9F12BD96D
Decrypted plaintext:
        C09EE67A237FC22C24E2A66413768C9DF935A9CEFF83AD03B32DFE314E77885FB62357DA4DD5A3B62558B3F8BA8E2A75323D0EDD828D525BFE204907CC37A46D
AES-GCM encryption/decryption test PASSED!

ECDH Key Exchange + HKDF + AES Encryption Demo completed successfully!
```

</details>
