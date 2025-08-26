AziHSM Sample - ECDH-KDF-AESCBC
===============================

This sample demonstrates the AziHSM in the following scenario:

1. Generate two ECDH public/private key pairs. (Each key pair represents a separate party: "Alice" (party 1) and "Bob" (party 2))
2. Perform ECDH key exchange, to exchange public keys between the two parties, and generate a shared secret.
3. Use KBKDF or HKDF to derive the same AES key (using the shared secret) for both parties.
    * KBKDF ("Key Based Key Derivation Function") refers to the **SP800-108 HMAC in counter mode** KDF, as seen [here](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation) in the NCrypt API documentation.
    * HKDF ("HMAC-based Key Derivation Function") is defined in [IETF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and is referred to in NCrypt by the `BCRYPT_HKDF_ALGORITHM` string.
    * **NOTE:** The user can choose between demonstrating KBKDF or HKDF via a command-line argument.
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

The sample accepts a single command-line argument, which is used to choose between the two KDFs (Key Derivation Functions) supported by AziHSM: KBKDF and HKDF.
Run the executable in one of the following ways:

```powershell
# Provide NO argument to choose KBKDF by default:
.\ECDH-KDF-AESCBC.exe

# To select KBKDF:
.\ECDH-KDF-AESCBC.exe KBKDF

# To select HKDF:
.\ECDH-KDF-AESCBC.exe HKDF
```

You should see output similar to this:

<details>
<summary>(Click here)</summary>

```
AziHSM Demonstration: ECDH Generate --> ECDH Exchange --> KDF AES --> AES-CBC Enc/Dec
=====================================================================================
Opened NCrypt Storage Provider handle: 0xbce1ce80

Step 1: ECHD Key Pair Generate
------------------------------
Generated ECDH key for Alice: 0xbce2a9e0
Generated ECDH key for Bob: 0xbce2a6a0

Step 2: ECDH Secret Exchange
----------------------------
Exported Alice's ECDH public key: 72 bytes of data
Exported Bob's ECDH public key: 72 bytes of data
Imported Alice's ECDH public key: 0xbce29be0
Imported Bob's ECDH public key: 0xbce29e60
Generated Alice's shared secret: 0xbce237b0
Generated Bob's shared secret: 0xbce237d0

Step 3: KBKDF AES
-----------------
Derived Alice's AES key: 0xbce2a5a0
Derived Bob's AES key: 0xbce2a320

Step 4: AES-CBC Encrypt/Decrypt
-------------------------------
Plaintext to be encrypted: [c8 90 a5 48 4e 89 48 6d cf 8a 4f 95 7a 0a 59 ec 54 e9 ef c9 cf f4 9a 1c 5b 28 af 8c 1e 8f fd 82 fb b3 4c d6 59 3c e3 86 40 5f b6 95 9d d2 b5 ac 5e 28 45 6c 3f 0a f2 6d 0a bf c9 20 08 fd 53 62 5e 36 d1 a8 4e fa 79 67 8f 06 3d 37 ec e3 7b 91 40 3b ff 7e 05 61 b4 dc 88 8b 6b 93 a3 f6 fd 47 3a 01 7e 37 2a bd 0f e4 59 eb b6 a2 e5 ec b4 19 91 4e 9a 84 24 3c 96 bd 04 03 b9 68 3c c7 17 9d]
AES-CBC Initialization Vector: [e7 e4 b3 e0 4b 73 9f 71 ca 68 4c b1 e0 fd 0d b4]
Encrypted plaintext with Alice's AES key: [d0 2e a1 6a 30 e9 0d fd 83 29 6b fc 4a e6 f4 a1 6d 38 03 cc 57 5d 2f a5 f9 87 ce bc 83 81 86 6f b1 d1 1d 77 fc 39 92 a3 ea 40 1a fb a1 e3 8c ce c7 f7 82 83 47 bf ed b3 01 fc be 4c 50 dc 7c 26 25 65 5b 1e c9 f0 89 38 a2 b8 0f 76 11 cb f0 00 9b bf 8f 6b d9 9c 10 cb 74 79 3c a3 bc 09 00 03 80 ce 8e 88 87 ef da 5d 93 44 36 df 74 87 80 cd e3 4c ec 25 12 cb c2 cf e3 1c 34 85 9d b8 64 d6]
Decrypted ciphertext with Bob's AES key: [c8 90 a5 48 4e 89 48 6d cf 8a 4f 95 7a 0a 59 ec 54 e9 ef c9 cf f4 9a 1c 5b 28 af 8c 1e 8f fd 82 fb b3 4c d6 59 3c e3 86 40 5f b6 95 9d d2 b5 ac 5e 28 45 6c 3f 0a f2 6d 0a bf c9 20 08 fd 53 62 5e 36 d1 a8 4e fa 79 67 8f 06 3d 37 ec e3 7b 91 40 3b ff 7e 05 61 b4 dc 88 8b 6b 93 a3 f6 fd 47 3a 01 7e 37 2a bd 0f e4 59 eb b6 a2 e5 ec b4 19 91 4e 9a 84 24 3c 96 bd 04 03 b9 68 3c c7 17 9d]
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

