# AziHSM Sample - RSA-IMPORT-ENCRYPT-DECRYPT

This sample demonstrates the AziHSM in the following scenario:

1. Import an RSA key into the AziHSM by wrapping it into an encrypted blob.
2. Use the imported RSA key to encrypt data.
3. Use the imported RSA key to decrypt data.

This shows the "bring your own key" process; how an external key can be imported into the AziHSM and used for crypto operations.

The RSA keys used here are pre-generated and stored in [RsaKeys.cs](./RsaKeys.cs).

> These keys are published in a public repository, and exist only so that the sample is self-contained. **Never use them to protect real data.**

## How to run

> See top-level [README.md](../README.md) for prerequisites.

The sample accepts a single command-line argument, which is used to choose between the three RSA key sizes supported by AziHSM: 2k (2048), 3k (3072), and 4k (4096).
Run the sample in one of the following ways:

```powershell
# Provide NO argument to choose RSA 2048 by default:
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release

# To select RSA 2048
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release -- 2048
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release -- 2k

# To select RSA 3072
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release -- 3072
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release -- 3k

# To select RSA 4096
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release -- 4096
dotnet run --project RSA-IMPORT-ENCRYPT-DECRYPT -c Release -- 4k
```

You should see output similar to this:

<details>
<summary>(Click here)</summary>

```
AziHSM Demonstration: RSA Key Import --> RSA Encrypt --> RSA Decrypt
====================================================================
The imported RSA key will have a length of 2048.

Step 1: Import RSA key
----------------------
Exported built-in unwrap public key: 539 bytes.
Key wrapped successfully. Key blob size: 1510 bytes.
Created wrapped RSA key blob: 1510 bytes of data.
Successfully imported key into AziHSM. Got handle: 0x178B9F20

Step 2: Encrypt Decrypt test
----------------------------
Encryption successful. Ciphertext length: 256
Decryption successful. Decrypted text length: 33
Encrypt-decrypt test passed!
Demo completed!
```

</details>

## Understanding the wrapped key blob

A private key is never handed to the device in the clear. Instead it is wrapped using the PKCS#11 `CKM_RSA_AES_KEY_WRAP` mechanism, so that only this specific AziHSM device is able to unwrap it.

Every AziHSM device has a built-in unwrapping key, named `AZIHSM_BUILTIN_UNWRAP_KEY`. Open it with `NCryptOpenKey`, then export its public half with `NCryptExportKey` to obtain the RSA public key that the blob is built against.

The blob is then assembled as follows:

1. Generate an ephemeral AES-256 key.
2. Encrypt that AES key with the device's RSA public key, using OAEP.
3. Wrap the private key with the AES key, using AES Key Wrap with Padding ([RFC 5649](https://datatracker.ietf.org/doc/html/rfc5649)).
4. Concatenate a header, the encrypted AES key, the wrapped private key, and the OAEP algorithm identifier.

Finally, import the blob with `NCryptImportKey` using the `PKCS11RsaAesWrapBlob` blob type.

Because only the AziHSM device holds the private half of the unwrapping key, only that device can recover the imported key.

In a real deployment, steps 1 to 4 are performed by whichever service holds the key; see the [SECURE-KEY-RELEASE](../SECURE-KEY-RELEASE/README.md) sample, where Azure Key Vault does the wrapping. This sample performs them locally so that it can run without any external infrastructure.

An imported RSA key can be used either for signing or for encryption, so the intended usage must be set with `NCryptSetProperty` after `NCryptImportKey` and before `NCryptFinalizeKey`. This sample sets `NCRYPT_ALLOW_DECRYPT_FLAG`.

The `RsaCrtEnabled` property is set at the same point. It enables the Chinese Remainder Theorem optimization, which makes RSA operations faster at the cost of more on-device storage per key. RSA keys are CRT-enabled by default.
