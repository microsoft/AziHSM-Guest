AziHSM Sample - ECDH-KDF-AESCBC
===============================

This sample demonstrates the AziHSM in the following scenario:

1. Generate two ECDH public/private key pairs. (Each key pair represents a separate party: "Alice" (party 1) and "Bob" (party 2))
2. Perform ECDH key exchange, to exchange public keys between the two parties, and generate a shared secret.
3. Use HKDF to derive the same AES key (using the shared secret) for both parties.
    * HKDF ("HMAC-based Key Derivation Function") is defined in [IETF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and is referred to in NCrypt by the `BCRYPT_HKDF_ALGORITHM` string.
4. Perform AES-CBC encryption and decryption to verify that the two derived AES keys are identical.

This scenario shows one way to utilize the AziHSM to establish a secure communication channel between two parties.

Even though both parties are represented within the same user-space process in this demonstration, this scenario can be applied to two completely separate/isolated parties to securely communicate with one another.

Building & Running the Code
---------------------------

### Prerequisite - AziHSM Dependencies

Before you can run this sample, you'll need to ensure you have all AziHSM dependencies installed onto your system.
Please the the installation guide under `docs/` in this repository.

### Building & Running

To build the code, you'll need to download both *this* sample's directory, as well as the `include/` directory, which contains the required header files.

We recommend downloading the entire `samples/` directory, to maintain the directory hierarchy expected by the individual Visual Studio projects.
(This Visual Studio project is configured to search for the AziHSM `include/` directory one level above the project directory. However, if necessary, [this can be changed in the project settings](https://learn.microsoft.com/en-us/cpp/build/working-with-project-properties).)

Locate the Visual Studio Solution (`.sln`) file within this directory.
Launch Visual Studio and open the Solution file.
This will populate Visual Studio with the sample project's contents.

Build and run the project with `F5`, or by selecting `Build > Build Solution`.
An executable will be produced within the project directory, which can be executed on the Windows command-line (PowerShell or Command Prompt).

The executable requires no command-line input; simply execute it like so:

```powershell
.\ECDH-KDF-AESCBC.exe
```

You should see output similar to this:

<details>
<summary>(Click here)</summary>

```
AziHSM Demonstration: ECDH Generate --> ECDH Exchange --> KDF AES --> AES-CBC Enc/Dec
=====================================================================================
Keys will be derived using HKDF.
Opened NCrypt Storage Provider handle: 0xb9f1dd50

Step 1: ECDH Key Pair Generate
------------------------------
Generated ECDH key for Alice: 0xb9f325b0
Generated ECDH key for Bob: 0xb9f31cf0

Step 2: ECDH Secret Exchange
----------------------------
Exported Alice's ECDH public key: 72 bytes of data
Exported Bob's ECDH public key: 72 bytes of data
Imported Alice's ECDH public key: 0xb9f32570
Imported Bob's ECDH public key: 0xb9f31a30
Generated Alice's shared secret: 0xb9f2c9f0
Generated Bob's shared secret: 0xb9f2c9b0

Step 3: HKDF AES
----------------
Derived Alice's AES key using HKDF: 0xb9f31b70
Derived Bob's AES key using HKDF: 0xb9f325f0

Step 4: AES-CBC Encrypt/Decrypt
-------------------------------
Plaintext to be encrypted: [bb e4 27 5f ce f0 04 5b 15 7e ab ba 8a bc 47 07 5b 0a 0c d1 6a e7 d3 a6 e8 77 13 13 3e a2 9f 6b b6 5e 77 96 26 63 fe 7f 72 2c 11 13 20 6d 8d e5 3b cb 2e 2e c6 05 56 0e f2 cf 4c 5b 8e 95 08 5b de 7a 21 1e dc d2 82 e4 8c e3 b2 cf 1a f8 1e c0 94 f9 6c 0a 57 5b 70 45 93 cd 66 9e 4a d2 00 4e 51 a4 05 32 88 4d e5 99 d8 90 57 07 71 8c db 41 1d 5a b1 26 f4 c6 58 3e d4 6c a6 de 47 09 7e 5e]
AES-CBC Initialization Vector: [1a cd 7c 08 e1 33 86 de 09 4e ed b0 92 1c 16 3b]
Encrypted plaintext with Alice's AES key: [c0 90 9e 76 7a 5f a7 5e 39 2a da 4c c6 bf ad 4c 7b 97 11 ec 4d 93 bd 34 8c c5 d8 3a 46 75 c2 a9 55 4d 4c b0 b1 bc 5b ee 56 16 64 e1 29 5b bb a0 18 03 1e 97 e9 6b 47 74 48 52 3f 8d ae 63 26 92 18 0a 53 fe 07 0e 56 49 c3 18 06 74 43 91 b2 9b 73 06 c4 6d 3b c8 35 b0 f2 17 3d c4 96 9b 50 31 63 cd 57 ef e7 fe c8 f5 19 d2 2d 32 50 0f 50 13 79 28 57 69 98 4e c4 28 6d 1b a4 25 a4 49 5a 4c]
Decrypted ciphertext with Bob's AES key: [bb e4 27 5f ce f0 04 5b 15 7e ab ba 8a bc 47 07 5b 0a 0c d1 6a e7 d3 a6 e8 77 13 13 3e a2 9f 6b b6 5e 77 96 26 63 fe 7f 72 2c 11 13 20 6d 8d e5 3b cb 2e 2e c6 05 56 0e f2 cf 4c 5b 8e 95 08 5b de 7a 21 1e dc d2 82 e4 8c e3 b2 cf 1a f8 1e c0 94 f9 6c 0a 57 5b 70 45 93 cd 66 9e 4a d2 00 4e 51 a4 05 32 88 4d e5 99 d8 90 57 07 71 8c db 41 1d 5a b1 26 f4 c6 58 3e d4 6c a6 de 47 09 7e 5e]
The decrypted ciphertext matches the original plaintext!

Cleaning Up
-----------
Freed Bob's decrypted ciphertext buffer.
Freed Alice's encrypted plaintext buffer.
Freed AES initialization vector copy.
Freed AES initialization vector.
Freed plaintext buffer.
Freed Bob's derved AES key handle.
Freed Alice's derved AES key handle.
Freed Bob's shared secret handle.
Freed Alice's shared secret handle.
Freed Bob's imported ECDH public key handle.
Freed Alice's imported ECDH public key handle.
Freed Bob's exported ECDH public key data buffer.
Freed Alice's exported ECDH public key data buffer.
Freed Bob's ECDH key handle.
Freed Alice's ECDH key handle.
Freed NCrypt Storage Provider handle.
Demo succeeded!
```

</details>

Included Header Files
---------------------

You'll notice that the sample's C++ file includes multiple header files:

* `AziHSM.h`
    * This header file defines several strings that are necessary for interfacing with the AziHSM via NCrypt.
    * For more information on this file, please see [this README](../include/AziHSM/README.md).
* `Utils.h`
    * This header file defines generic helper functions used by this sample and others.

