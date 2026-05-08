# AziHSM Sample - ATTEST-UNWRAP-KEY

This sample will demonstrate a **mocked** Secure Key Release flow for AziHSM, where user attests AziHSM and securely imports their private key from external services like Azure Key Vault.

External dependencies like Microsoft Azure Attestation and Azure Key Vault are mocked, so you can run this sample locally without additional setup. This also enables you to import any RSA or ECDSA key into AziHSM for quick experiments.

> For real-world Secure Key Release sample, see SECURE-KEY-RELEASE.cpp

This sample demonstrates the AziHSM in the following scenario:

1. Fetch quote and collateral from AziHSM.
2. Send quote and collateral to external service(mocked) for attestation
   verification, get attestation token in return.
3. Send (1)attestation token, (2)link to private key and (3)import key
   to external service(mocked) for key wrapping and release.
4. Import the wrapped key (You can choose between RSA and ECDSA key in this sample).
5. Perform typical workload like hash signing and verification using the
   imported RSA key.

## How to run

> See top-level [README.md](../README.md) for prerequisites.

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

Working with RSA key.

Step 1: Get Quote and Collateral
--------------------------------

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
