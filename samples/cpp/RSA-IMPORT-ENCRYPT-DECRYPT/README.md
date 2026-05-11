# AziHSM Sample - RSA-IMPORT-ENCRYPT-DECRYPT

This sample demonstrates the AziHSM in the following scenario:

1. Import an RSA key into the AziHSM by wrapping it into an encrypted blob.
2. Use the imported RSA key to encrypt data.
3. Use the imported RSA key to decrypt data.

This shows the "bring your own key" process; how an external key can be imported into the AziHSM and used for crypto operations.

## How to run

> See top-level [README.md](../README.md) for prerequisites.

The sample accepts a single command-line argument, which is used to choose between the three RSA key sizes supported by AziHSM: 2k (2048), 3k (3072), and 4k (4096).
Run the executable in one of the following ways:

```powershell
# Provide NO argument to choose RSA 2048 by default:
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe

# To select RSA 2048
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe 2048
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe 2k

# To select RSA 3072
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe 3072
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe 3k

# To select RSA 4096
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe 4096
.\RSA-IMPORT-ENCRYPT-DECRYPT.exe 4k
```

You should see output similar to this:

<details>
<summary>(Click here)</summary>

```
AziHSM Demonstration: RSA Key Import --> RSA Encrypt --> RSA Decrypt
====================================================================
The imported RSA key will have a length of 2048.
Key wrapped successfully. Key Blob Size: 1510 bytes.
Created wrapped RSA key blob: 1510 bytes of data.
Successfully imported key into AziHSM. Got handle: 1617969998048

Step 2: Encrypt Decrypt test
-------------------------
Encryption successful. Ciphertext length: 256
Decryption successful. Decrypted Text length: 33
Encrypt-decrypt test passed!
Demo completed!
```
