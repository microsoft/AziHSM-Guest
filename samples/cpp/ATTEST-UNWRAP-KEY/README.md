AziHSM Sample - ATTEST-UNWRAP-KEY
===============================

This sample demonstrates the AziHSM in the following scenario:

1. Fetch quote and collateral from AziHSM.
2. Send quote and collateral to external service(mocked) for attestation
   verification, get attestation token in return.
3. Send (1)attestation token, (2)link to private key and (3)import key
   to external service(mocked) for key wrapping and release.
4. Import the wrapped key (You can choose between RSA and ECDSA key in this sample).
5. Perform typical workload like hash signing and verification using the
   imported RSA key.

This sample shows the Secure Key Release flow, where user attests AziHSM and securely imports their private key from external services like Azure Key Vault. 
*Please note that [Microsoft Azure Attestation Service](https://learn.microsoft.com/en-us/azure/attestation/overview) does not support AziHSM attestation as of today, so attestation is mocked. Without the attestation token from Microsoft Azure Attestation Service, we are unable to perform a secure key release from [Azure Manged HSM Service](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview) and therefore we are mocking that as well.*

Building & Running the Code
---------------------------

### Prerequisite - AziHSM Dependencies

Before you can run this sample, you'll need to ensure you have all AziHSM dependencies installed onto your system.
Please the the installation guide under `docs/` in this repository.

### Building & Running

To build the code, you'll need to download both *this* sample's directory, as well as the `include/` directory, which contains the required header files.

We recommend downloading the entire `samples/` directory, to maintain the directory hierarchy expected by the individual Visual Studio projects.
(This Visual Studio project is configured to search for the AziHSM `include/` directory one level above the project directory. However, if necessary, [this can be changed in the project settings](https://learn.microsoft.com/en-us/cpp/build/working-with-project-properties).)

Open `ATTEST-UNWRAP-KEY.sln` with Visual Studio to view the project.

The sample accepts a single command-line argument, which is used to choose between two key types: RSA and ECDSA.
Run the executable in one of the following ways:

```powershell
# Provide NO argument to choose RSA by default:
.\ATTEST-UNWRAP-KEY.exe

# To select ECDSA:
.\ATTEST-UNWRAP-KEY.exe ECDSA

# To select RDSA:
.\ATTEST-UNWRAP-KEY.exe RSA
```

You should see output similar to this:

<details>
<summary>(Click here)</summary>

```
AziHSM Demonstration:
Get Quote/Collateral --> Mock Attestation --> Mock Key Wrap and Release --> Import --> Sign/Verify
==================================================================================================
*Please note that [Microsoft Azure Attestation Service](https://learn.microsoft.com/en-us/azure/attestation/overview) does not support AziHSM attestation as of today, so attestation is mocked. Without the attestation token from Microsoft Azure Attestation Service, we are unable to perform a secure key release from [Azure Manged HSM Service](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview) and therefore we are mocking that as well.*

No key type specified. Defaulting to import RSA key.
Usage:
    ATTEST-UNWRAP-KEY.exe [rsa|ecdsa]

Working with RSA key.

Step 1: Get Quote and Collateral
--------------------------------
Opened NCrypt Storage Provider handle: 0xd4c5b640

Step 2: Mock Attestation
------------------------
Quote: 834 bytes. Collateral: 619 bytes.

Step 3: Mock Key Wrap and Release
---------------------------------
Key wrapped successfully. Key Blob Size: 1518 bytes.

Step 4: Import Wrapped Key
--------------------------

Step 5: Sign with imported key and Verify
-----------------------------------------
Signature size: 256 bytes.
Signature internally verified successfully.
Signature matches pre-calculated value

Sample finished successfully
----------------------------

Done Cleaning Up
----------------
```

</details>

### Understanding the claim buffer

With a successful call to `NCryptCreateClaim`, it will write output to the claim buffer, pointed to by `pbClaimBlob`.
```c
SECURITY_STATUS NCryptCreateClaim(
  [in]           NCRYPT_KEY_HANDLE hSubjectKey,
  [in, optional] NCRYPT_KEY_HANDLE hAuthorityKey,
  [in]           DWORD             dwClaimType,
  [in, optional] NCryptBufferDesc  *pParameterList,
  [out]          PBYTE             pbClaimBlob,
  [in]           DWORD             cbClaimBlob,
  [out]          DWORD             *pcbResult,
  [in]           DWORD             dwFlags
);
```

The output contains binary data with following format
```
// (all numbers are in little-endian):
// - Header
// - 4 bytes: UINT32, version, currently 1
// - 4 bytes: UINT32, buffer total length, including header
// - 4 bytes: UINT32, length of attestation report in bytes
// - 4 bytes: UINT32, length of certificate in bytes
// - Payload
// - N bytes: attestation report
// - M bytes: certificate
```

To parse it, you can use the helper function `azihsm_parse_claim` from header file `AziHSM.h`.

The attestation report wil be a binary data with opaque format.  
The certificate will be a text blob of multiple X.509 certificates in PEM format, separated by newline `\n`.


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
