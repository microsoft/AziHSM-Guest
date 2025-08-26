AziHSM Sample - RSA-IMPORT-ENCRYPT-DECRYPT
==========================================

This sample demonstrates the AziHSM in the following scenario:

1. Import an RSA key into the AziHSM by wrapping it into an encrypted blob.
2. Use the imported RSA key to encrypt data.
3. Use the imported RSA key to decrypt data.

This shows the "bring your own key" process; how an external key can be imported into the AziHSM and used for crypto operations.

Building & Running the Code
---------------------------

### Prerequisite - AziHSM Dependencies

Before you can run this sample, you'll need to ensure you have all AziHSM dependencies installed onto your system.
Please the the installation guide under `docs/` in this repository.

### Building & Running

To build the code, you'll need to download both *this* sample's directory, as well as the `include/` directory, which contains the required header files.

We recommend downloading the entire `samples/` directory, to maintain the directory hierarchy expected by the individual Visual Studio projects.
(This Visual Studio project is configured to search for the AziHSM `include/` directory one level above the project directory. However, if necessary, [this can be changed in the project settings](https://learn.microsoft.com/en-us/cpp/build/working-with-project-properties).)

Open `RSA-IMPORT-ENCRYPT-DECRYPT.sln` with Visual Studio to view the project.

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
Opened NCrypt Storage Provider handle: 0xb8b5c140

Step 1: Import RSA Key
----------------------
Opened handle to built-in unwrap key: 0xb8b5dcb0.
Key wrapped successfully. Key Blob Size: 1510 bytes.
Created wrapped RSA key blob: 1510 bytes of data.
Successfully imported key into AziHSM. Got handle: 0xb8b6deb0.

Step 2: Encrypt Plaintext
-------------------------
Plaintext to be encrypted: [c1 7a 73 12 cd 85 98 c1 8f 1b 84 fc b7 70 17 f3 20 43 40 de 54 ea 89 20 b9 28 f3 fc 64 63 0a ac f1 23 a1 5b 05 7d e5 9a 5a 13 d7 7d 8b 0a 77 8b 10 28 13 2e 96 c3 aa e9 d9 db bb 8c 51 0d 05 01 9c a1 b0 da e2 2c db 0a bd 93 f9 86 6a 52 f2 64 94 5d d9 55 2f 40 26 e8 5d ca 4f df 0b 6f 3a 61 97 04 41 17 2b af b6 07 15 4a 0b 5d ea 3f 0f 54 5a 0d 5e 92 2a 98 94 f3 34 64 50 e0 f5 30 b8 b0]
Successfully encrypted plaintext: 256 bytes of ciphertext.
Ciphertext: [2c b0 0f 17 e3 15 4b a8 ff a4 4c f2 43 91 3a 5f 36 49 9b fb 36 ed a2 81 28 22 95 47 a8 48 0c 6b 58 d7 c7 ec d2 3b 57 8f 89 24 cc df 0b e6 18 53 9d 4d 3f 5a d9 a4 2b 96 3c 1a 16 fc fb 63 7e 6b d5 c2 5a b0 30 d3 50 e8 f3 a6 cc 35 a4 9b ab 35 c1 ca b6 2d b8 ee 7c 72 7a 3d be 92 2d b1 84 27 75 24 13 3e 0c b7 16 7c f2 16 27 ae b7 fb f2 d8 ec c8 b5 a5 1d fc 2b 05 88 b9 16 2e 23 46 fc 20 30 59 8e 9b cd b4 5b b6 f2 94 63 31 8e 27 63 25 9f 02 a9 16 69 62 9e 6e ab 61 b1 4a d6 55 19 24 fa 05 07 f9 c2 95 ab 8d dc b1 ad 25 ea ba 9a 76 c0 88 a8 23 73 1b 39 0b c4 49 bc a0 96 70 47 9e 35 5f db 83 f1 0c ae de ae f9 b8 98 03 f7 c1 c9 8e 15 5a f0 a6 0d 7a 25 bf 11 2a e2 92 e0 5e 6f d4 da cb 0f 1e fe e6 81 5b d2 62 46 15 bc e2 02 ec 73 67 a6 f9 aa 3e 48 68 bf 97 89 b0 7e 0f 4f]

Step 3: Decrypt Ciphertext
--------------------------
Successfully decrypted ciphertext: 128 bytes of plaintext.
Decrypted plaintext: [c1 7a 73 12 cd 85 98 c1 8f 1b 84 fc b7 70 17 f3 20 43 40 de 54 ea 89 20 b9 28 f3 fc 64 63 0a ac f1 23 a1 5b 05 7d e5 9a 5a 13 d7 7d 8b 0a 77 8b 10 28 13 2e 96 c3 aa e9 d9 db bb 8c 51 0d 05 01 9c a1 b0 da e2 2c db 0a bd 93 f9 86 6a 52 f2 64 94 5d d9 55 2f 40 26 e8 5d ca 4f df 0b 6f 3a 61 97 04 41 17 2b af b6 07 15 4a 0b 5d ea 3f 0f 54 5a 0d 5e 92 2a 98 94 f3 34 64 50 e0 f5 30 b8 b0]
The decrypted ciphertext matches the original plaintext!

Cleaning Up
-----------
Freed decrypted ciphertext buffer.
Freed ciphertext buffer.
Freed plaintext buffer.
Freed imported key handle.
Freed wrapped key blob data.
Freed built-in unwrap key handle.
Freed NCrypt Storage Provider handle.
Demo succeeded!
```

Included Header Files
---------------------

You'll notice that the sample's C++ file includes multiple header files:

* `AziHSM.h`
    * This header file defines several strings that are necessary for interfacing with the AziHSM via NCrypt.
    * For more information on this file, please see [this README](../include/AziHSM/README.md).
* `RsaWrapUtils.h`
    * This header file defines helper functions related to exporting a RSA key in the PKCS#11 format.
* `Utils.h`
    * This header file defines generic helper functions used by other samples.
