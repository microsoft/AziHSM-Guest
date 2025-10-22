// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check readme.md for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Fetch quote and collateral from AziHSM.
// 2. Send quote and collateral to external service(mocked) for attestation
//    verification, get attestation token in return.
// 3. Send (1)attestation token, (2)link to private key and (3)import key
//    to external service(mocked) for key wrapping and release.
// 4. Import the wrapped key (You can choose between RSA and ECDSA key in this sample).
// 5. Perform typical workload like hash signing and verification using the
//    imported key.
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

// Use `WIN32_NO_STATUS` to prevent macro-redefinition warnings in `ntstatus.h`
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>
#include <ncrypt.h>

#include <cstdio>

#include "AziHSM/AziHSM.h"
#include "Utils/RsaWrapUtils.h"

#include "RsaKey.h"
#include "EcdsaKey.h"

// Force the linking of the NCrypt library into this executable, so we can
// access NCrypt symbols in our code below:
#pragma comment(lib, "ncrypt.lib")

enum KeyType {
    KEY_TYPE_RSA,
    KEY_TYPE_ECDSA
};

// Fetch quote and Collateral from AziHSM
// Quote and Collateral will be in a opaque format
// Caller is responsible to free the two output buffers
static SECURITY_STATUS get_quote_and_certificate(
    NCRYPT_PROV_HANDLE provider,
    NCRYPT_KEY_HANDLE importKey,
    char userdata[128],
    PBYTE* outBufferQuote,
    DWORD* outBufferQuoteSize,
    PBYTE* outBufferCertificate,
    DWORD* outBufferCertificateSize)
{
    SECURITY_STATUS status = E_FAIL;
    AZIHSM_STATUS azihsm_status = AZIHSM_FAILURE;

    DWORD bytesWritten = 0;

    PBYTE bufferClaim = NULL;
    DWORD bufferClaimSize = 0;

    // Offset in bufferClaim
    // Quote == bufferClaim[bufferQuoteOffset, bufferQuoteOffset + bufferQuoteSize]
    DWORD bufferQuoteOffset = NULL;
    DWORD bufferQuoteSize = 0;

    // Offset to bufferClaim
    // Certificate == bufferClaim[bufferCertificateOffset, bufferCertificateOffset + bufferCertificateSize]
    DWORD bufferCertificateOffset = NULL;
    DWORD bufferCertificateSize = 0;

    // A fixed-size (128 bytes) buffer that will be copied into the quote
    // This buffer is used to provide a nonce for the quote generation.
    BCryptBuffer bcryptBuffer = { 128, NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, userdata };
    NCryptBufferDesc paramBuffers = { NCRYPTBUFFER_VERSION, 1, &bcryptBuffer };

    // Use NCryptCreateClaim to obtain the unwrapping key attestation report + certificate chain
    // Get size of the output buffer
    status = NCryptCreateClaim(importKey, NULL, 0, &paramBuffers, NULL, 0, &bytesWritten, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get quote size. NCryptCreateClaim returned: 0x%08x\n", status);
        goto cleanup;
    }

    bufferClaimSize = bytesWritten;
    bufferClaim = new BYTE[bufferClaimSize];

    // Get quote and certificate
    status = NCryptCreateClaim(importKey, NULL, 0, &paramBuffers, bufferClaim, bufferClaimSize, &bytesWritten, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get claim size. NCryptCreateClaim returned: 0x%08x\n", status);
        goto cleanup;
    }
    // The allocated buffer size may be larger than the actual quote size, so we update the size
    bufferClaimSize = bytesWritten;

    azihsm_status = azihsm_parse_claim(bufferClaim, bufferClaimSize,
        &bufferQuoteOffset, &bufferQuoteSize,
        &bufferCertificateOffset, &bufferCertificateSize);

    if (AZIHSM_SUCCESS != azihsm_status) {
        fprintf(stderr, "Failed to parse claim buffer, status: %d\n", azihsm_status);
        goto cleanup;
    }

    // Return copy of quote + certificate so we can free the buffer returned from NCryptCreateClaim
    *outBufferQuote = new BYTE[bufferQuoteSize];
    *outBufferQuoteSize = bufferQuoteSize;
    memcpy(*outBufferQuote, bufferClaim + bufferQuoteOffset, bufferQuoteSize);

    *outBufferCertificate = new BYTE[bufferCertificateSize];
    *outBufferCertificateSize = bufferCertificateSize;
    memcpy(*outBufferCertificate, bufferClaim + bufferCertificateOffset, bufferCertificateSize);

    status = S_OK;
cleanup:
    if (bufferClaim)
    {
        delete[] bufferClaim;
    }

    return status;
}

// You should not care about the implementation of this function
// As it mocks the behavior of an external service that
// 1. Verifies the quote and collateral
// 2. Returns an attestation token
static HRESULT mock_attestation(
    PBYTE quoteBuffer,
    DWORD quoteBufferSize,
    PBYTE collateralBuffer,
    DWORD collateralBufferSize,
    int* token)
{
    // Dump quote and collateral size
    printf("Quote: %lu bytes. Collateral: %lu bytes.\n", quoteBufferSize, collateralBufferSize);

    // Skip actual attestation or verification of the quote and collateral
    // Return a mock attestation token, this typically is a JWT
    // Using a number here for simplicity
    *token = 123;

    return S_OK;
}

// You should not care about the implementation of this function
// As it mocks the behavior of an external service that
// 1. Verifies the attestation token
// 2. Obtain the private key from the link
// 3. Wraps the private key, given the public part of the AziHSM's unwrap/import key
// 4. Returns the wrapped key blob (BCRYPT_PKCS11_RSA_AES_WRAP_BLOB)
//
// Why we need importKey here?
// The importKey handle is only needed for mocking purposes.
// The external service would typically obtain import key from attestation token.
static SECURITY_STATUS mock_key_wrap_and_release(
    KeyType keyType,
    int attestationToken,
    char* linkToPrivateKey,
    NCRYPT_KEY_HANDLE importKey,
    PBYTE* outBufferKeyBlob,
    DWORD* outBufferKeyBlobSize)
{
    SECURITY_STATUS status = E_FAIL;

    // The hash algorithm ID during key wrap
    // All options:
    // NCRYPT_SHA1_ALGORITHM
    // NCRYPT_SHA256_ALGORITHM
    // NCRYPT_SHA384_ALGORITHM
    // NCRYPT_SHA512_ALGORITHM
    LPCWSTR hashAlgId = NCRYPT_SHA256_ALGORITHM;

    DWORD bytesWritten = 0;
    // Public key of Import Key in BCrypt format
    PBYTE bufferImportKey = NULL;
    DWORD bufferImportKeySize = 0;

    // Buffer to hold the Private Key (DER format) to be imported
    PBYTE bufferToBeImportedKey = NULL;
    DWORD bufferToBeImportedKeySize = 0;

    if (keyType == KeyType::KEY_TYPE_RSA)
    {
        bufferToBeImportedKey = (PBYTE)PRIVATE_KEY_RSA;
        bufferToBeImportedKeySize = sizeof(PRIVATE_KEY_RSA);
    }
    else {
        bufferToBeImportedKey = (PBYTE)PRIVATE_KEY_ECDSA;
        bufferToBeImportedKeySize = sizeof(PRIVATE_KEY_ECDSA);
    }

    // Mock verification of the attestation token
    if (attestationToken == 0)
    {
        fprintf(stderr, "Invalid attestation token: %d\n", attestationToken);
        status = NTE_BAD_DATA;
        goto cleanup;
    }

    // Mock fetching the private key from the link
    if (linkToPrivateKey == NULL)
    {
        fprintf(stderr, "Invalid link to private key\n");
        status = NTE_BAD_DATA;
        goto cleanup;
    }

    // Get Public Key of Import Key
    status = NCryptExportKey(importKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &bytesWritten, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get public key size. NCryptExportKey returned: 0x%08x\n", status);
        goto cleanup;
    }

    bufferImportKeySize = bytesWritten;
    bufferImportKey = new BYTE[bufferImportKeySize];

    status = NCryptExportKey(importKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        bufferImportKey,
        bufferImportKeySize,
        &bytesWritten,
        0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get public key size. NCryptExportKey returned: 0x%08x\n", status);
        goto cleanup;
    }
    bufferImportKeySize = bytesWritten;

    // Wrap and export private Key
    status = HRESULT_FROM_NT(ExportKeyWrapped(bufferToBeImportedKey,
        bufferToBeImportedKeySize,
        bufferImportKey,
        bufferImportKeySize,
        hashAlgId,
        outBufferKeyBlob,
        outBufferKeyBlobSize));
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to wrap key. ExportKeyWrapped returned: 0x%08x\n", status);
        goto cleanup;
    }

    status = S_OK;
cleanup:

    if (bufferImportKey)
    {
        delete[] bufferImportKey;
    }

    return status;
}

// You can import a wrapped key presented by BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
// You also need to set key property during import
// 
// bufferKeyBlob: a buffer containing BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
// 
// keyUsage: can be one of:
//     NCRYPT_ALLOW_DECRYPT_FLAG: Allow Encrypt/Decrypt
//     NCRYPT_ALLOW_SIGNING_FLAG: Allow Sign/Verify
//     NCRYPT_ALLOW_KEY_IMPORT_FLAG: Allow importing keys
static SECURITY_STATUS import_wrapped_key(
    KeyType keyType,
    NCRYPT_PROV_HANDLE provider,
    NCRYPT_KEY_HANDLE importKey,
    PBYTE bufferKeyBlob,
    DWORD bufferKeyBlobSize,
    DWORD keyUsage,
    NCRYPT_KEY_HANDLE* outImportedKey)
{
    SECURITY_STATUS status = E_FAIL;

    NCRYPT_KEY_HANDLE importedKey = NULL;

    // Pick the algorithm same as the type of key you wish to import
    LPCWSTR algo = (keyType == KeyType::KEY_TYPE_RSA) ? BCRYPT_RSA_ALGORITHM : BCRYPT_ECDSA_P256_ALGORITHM;
    NCryptBuffer paramBuffers[] = {
        {(ULONG)((wcslen(algo) + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_ALG_ID, (PVOID)algo} };
    NCryptBufferDesc paramBuffer = { NCRYPTBUFFER_VERSION, 1, paramBuffers };

    // Import Key blob
    status = NCryptImportKey(provider,
        importKey,
        BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
        &paramBuffer,
        &importedKey,
        bufferKeyBlob,
        bufferKeyBlobSize,
        NCRYPT_DO_NOT_FINALIZE_FLAG);
    if (FAILED(status))
    {
        printf("Failed to import key blob. NCryptImportKey returned: 0x%08x\n", status);
        goto cleanup;
    }

    if (keyType == KeyType::KEY_TYPE_RSA) {
        // RSA key can be used for signing or encryption
        // We need to explictly set the usage
        // Here we want to use the imported RSA key for signing
        status = NCryptSetProperty(importedKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), 0);
        if (FAILED(status))
        {
            printf("Failed to set Signing for imported RSA Key. NCryptSetProperty returned: 0x%08x\n", status);
            goto cleanup;
        }

        // Optionally, we can set the RSA key to be CRT-enabled
        // This is an optimization that allows for faster RSA operations
        // At the cost of requiring more space to store the key
        {
            status = NCryptSetProperty(importedKey,
                AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_NAME,
                (PBYTE)&AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED,
                sizeof(uint32_t),
                0);
            if (FAILED(status))
            {
                printf("Failed to set CRT-enabled for RSA key. NCryptSetProperty returned: 0x%08x\n", status);
                goto cleanup;
            }
        }
    }
    else {
        // No need to set usage for ECDSA key
    }

    status = NCryptFinalizeKey(importedKey, 0);
    if (FAILED(status))
    {
        printf("Failed to finialize imported Key. NCryptFinalizeKey returned: 0x%08x\n", status);
        goto cleanup;
    }

    *outImportedKey = importedKey;
    importedKey = NULL;
    status = S_OK;

cleanup:
    if (importedKey)
    {
        NCryptFreeObject(importedKey);
    }
    return status;
}

// Use the imported key to sign something and verify
// Use RSA Key
static SECURITY_STATUS sign_verify_rsa(
    NCRYPT_KEY_HANDLE importedKey,
    DWORD bufferHashSize,
    LPCWSTR hashAlgId,
    PBYTE* outBufferSignature,
    DWORD* outBufferSignatureSize)
{
    SECURITY_STATUS status = E_FAIL;

    // For padding, we can either use
    DWORD flagPadding = NCRYPT_PAD_PKCS1_FLAG;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { hashAlgId };

    // Or
    // DWORD flagPadding = NCRYPT_PAD_PSS_FLAG;
    // BCRYPT_PSS_PADDING_INFO paddingInfo = { hashAlgId , <random number less than bufferHashSize>};

    PBYTE bufferHash = new BYTE[bufferHashSize];
    memset(bufferHash, 0, bufferHashSize);
    // Use pre-defined hash for easy verification
    memcpy(bufferHash, MESSAGE_RSA, sizeof(MESSAGE_RSA));

    PBYTE bufferSignature = NULL;
    DWORD bufferSignatureSize = 0;
    DWORD bytes = 0;

    status = NCryptSignHash(importedKey,
        &paddingInfo,
        bufferHash,
        bufferHashSize,
        NULL,
        0,
        &bytes,
        flagPadding);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get signature size when signing. NCryptSignHash returned: 0x%08x\n", status);
        goto cleanup;
    }

    bufferSignatureSize = bytes;
    bufferSignature = new BYTE[bufferSignatureSize];
    status = NCryptSignHash(importedKey,
        &paddingInfo,
        bufferHash,
        bufferHashSize,
        bufferSignature,
        bufferSignatureSize,
        &bytes,
        flagPadding);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to sign hash. NCryptSignHash returned: 0x%08x\n", status);
        goto cleanup;
    }
    printf("Signature size: %lu bytes.\n", bytes);
    bufferSignatureSize = bytes;

    // Verify itself
    status = NCryptVerifySignature(importedKey,
        &paddingInfo,
        bufferHash,
        bufferHashSize,
        bufferSignature,
        bufferSignatureSize,
        flagPadding);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to verify signature. NCryptVerifySignature returned: 0x%08x\n", status);
        goto cleanup;
    }
    printf("Signature internally verified successfully.\n");

    *outBufferSignature = bufferSignature;
    bufferSignature = NULL;
    *outBufferSignatureSize = bufferSignatureSize;

    status = S_OK;
cleanup:

    if (bufferSignature)
    {
        delete[] bufferSignature;
    }

    if (bufferHash)
    {
        delete[] bufferHash;
    }

    return status;
}

// Use the imported key to sign something and verify
// Use ECDSA Key
// The signature is in raw format (r s), not ASN.1 encoded
static SECURITY_STATUS sign_verify_ecdsa(
    NCRYPT_KEY_HANDLE importedKey,
    DWORD bufferHashSize,
    PBYTE* outBufferSignature,
    DWORD* outBufferSignatureSize)
{
    SECURITY_STATUS status = E_FAIL;

    PBYTE bufferHash = new BYTE[bufferHashSize];
    memset(bufferHash, 0, bufferHashSize);
    memcpy(bufferHash, MESSAGE_ECDSA, sizeof(MESSAGE_ECDSA));

    PBYTE bufferSignature = NULL;
    DWORD bufferSignatureSize = 0;
    DWORD bytes = 0;

    status = NCryptSignHash(importedKey,
        NULL,
        bufferHash,
        bufferHashSize,
        NULL,
        0,
        &bytes,
        0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get signature size when signing. NCryptSignHash returned: 0x%08x\n", status);
        goto cleanup;
    }

    bufferSignatureSize = bytes;
    bufferSignature = new BYTE[bufferSignatureSize];
    status = NCryptSignHash(importedKey,
        NULL,
        bufferHash,
        bufferHashSize,
        bufferSignature,
        bufferSignatureSize,
        &bytes,
        0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to sign hash. NCryptSignHash returned: 0x%08x\n", status);
        goto cleanup;
    }
    printf("Signature size: %lu bytes.\n", bytes);
    bufferSignatureSize = bytes;

    // Verify itself
    status = NCryptVerifySignature(importedKey,
        NULL,
        bufferHash,
        bufferHashSize,
        bufferSignature,
        bufferSignatureSize,
        0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to verify signature. NCryptVerifySignature returned: 0x%08x\n", status);
        goto cleanup;
    }
    printf("Signature internally verified successfully.\n");

    *outBufferSignature = bufferSignature;
    bufferSignature = NULL;
    *outBufferSignatureSize = bufferSignatureSize;

    status = S_OK;
cleanup:

    if (bufferSignature)
    {
        delete[] bufferSignature;
    }

    if (bufferHash)
    {
        delete[] bufferHash;
    }

    return status;
}

// Helper function that determines which Key Type to use
// during execution, based on the command-line arguments provided by the user.
static KeyType parse_key_type(int argc, char** argv)
{
    KeyType result = KEY_TYPE_RSA;

    // If no command-line arguments are provided, default to RSA
    if (argc == 1) {
        printf("No key type specified. Defaulting to import RSA key.\n");
        printf("Usage:\n    %s [rsa|ecdsa]\n", argv[0]);
        return result;
    }

    // Iterate through each command-line argument (skipping the first, which is
    // the executable path) and look for either "RSA" or "ECDSA". Convert
    // strings to lowercase to allow for case insensitive matches.
    for (int i = 1; i < argc; i++)
    {
        char* arg = argv[i];

        // Make a copy of the argument string, and convert it to lowercase
        size_t str_len = std::strlen(arg);
        char* str = new char[str_len + 1];
        for (size_t j = 0; j < str_len; j++)
        {
            str[j] = std::tolower(static_cast<unsigned char>(arg[j]));
        }
        str[str_len] = '\0';

        // Does the string match? If so, update the return value
        if (!strcmp(str, "rsa"))
        {
            result = KEY_TYPE_RSA;
        }
        else if (!strcmp(str, "ecdsa"))
        {
            result = KEY_TYPE_ECDSA;
        }

        delete[] str;
    }

    return result;
}

int main(int argc, char** argv)
{
    printf("\n\nAziHSM Demonstration:\nGet Quote/Collateral --> Mock Attestation --> Mock Key Wrap and Release --> Import "
        "--> Sign/Verify\n");
    printf("==================================================================================================\n");

    HRESULT status = E_FAIL;

    // Import the RSA or ECDSA key in this sample?
    KeyType keyType = parse_key_type(argc, argv);
    if (keyType == KeyType::KEY_TYPE_RSA) {
        printf("\nWorking with RSA key.\n");
    }
    else {
        printf("\nWorking with ECDSA key.\n");
    }

    // AziHSM Provider
    NCRYPT_PROV_HANDLE provider = NULL;
    // AziHSM Builtin Import Key
    NCRYPT_KEY_HANDLE importKey = NULL;
    // Handle to the RSA key to be imported
    NCRYPT_KEY_HANDLE importedKey = NULL;

    // A buffer to be copied into the AziHSM quote
    // This should be a unique value like hash of some other stuff
    // So user knows the quote is freshly generated for them
    char userdata[128] = "Put your custom data here to be included in the quote. For example hash";
    // quote from AziHSM
    PBYTE bufferQuote = NULL;
    DWORD bufferQuoteSize = 0;
    // collateral from AziHSM, it contains certificate chain
    PBYTE bufferCollateral = NULL;
    DWORD bufferCollateralSize = 0;

    // (Mocked) Attestation Token
    // Usually should be a JWT
    int attestationToken = 0;
    // (Mocked) Link to the private key user wishes to Secure Key Release and Import into AziHSM
    // In a real-world scenario, this would be a link to a private key stored in Azure Key Vault, for example.
    char linkToPrivateKey[256] = "http://link/to/private/key/you/wish/to/import";

    // The wrapped key blob (returned from Azure Key Vault, for example)
    // This buffer should contain BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
    PBYTE bufferKeyBlob = NULL;
    DWORD bufferKeyBlobSize = 0;

    // For RSA signing
    // Pick the hash size and hash algorithm
    // This should be set according to Hash Algorithm
    // SHA256: 32
    // SHA384: 48
    // SHA512: 64
    DWORD hashSizeRsa = 32;
    LPCWSTR hashAlgId = BCRYPT_SHA256_ALGORITHM;

    // For ECDSA signing
    // Pick the hash size
    // This should be set according to ECC Key Curve Type
    // P256: 32
    // P384: 48
    // P521: 68
    // Using 32 here as the ECDSA key in this sample is P256
    DWORD hashSizeEcdsa = 32;

    // Signature generated during Signing
    PBYTE bufferSignature = NULL;
    DWORD bufferSignatureSize = 0;

    printf("\nStep 1: Get Quote and Collateral"
        "\n--------------------------------\n");

    // To use AziHSM, you need to open "Microsoft Azure Integrated HSM Key Storage Provider"
    status = NCryptOpenStorageProvider(&provider, AZIHSM_KSP_NAME, 0);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to open NCrypt Storage Provider handle. "
            "NCryptOpenStorageProvider returned: 0x%08x\n",
            status);
        goto cleanup;
    }
    printf("Opened NCrypt Storage Provider handle: 0x%08x\n", (int)provider);

    // Obtain the public part of built-in unwrapping key
    // We will send this key to the external service for key wrapping and release
    status = NCryptOpenKey(provider, &importKey, AZIHSM_BUILTIN_UNWRAP_KEY_NAME, 0, 0);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to open Import Key handle. "
            "NCryptOpenKey returned: 0x%08x\n",
            status);
        goto cleanup;
    }

    status = get_quote_and_certificate(provider,
        importKey,
        userdata,
        &bufferQuote,
        &bufferQuoteSize,
        &bufferCollateral,
        &bufferCollateralSize);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to get quote and certificate. "
            "get_quote_and_certificate returned: 0x%08x\n",
            status);
        goto cleanup;
    }

    printf("\nStep 2: Mock Attestation"
        "\n------------------------\n");
    // In a real-world scenario, you would send the quote and collateral to
    // an external service for attestation verification.
    // Here we just dump the quote and collateral and return a mock attestation token.
    status = mock_attestation(bufferQuote, bufferQuoteSize, bufferCollateral, bufferCollateralSize, &attestationToken);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to mock attestation. "
            "mock_attestation returned: 0x%08x\n",
            status);
        goto cleanup;
    }

    printf("\nStep 3: Mock Key Wrap and Release"
        "\n---------------------------------\n");
    // In a real-world scenario, you would send the attestation token,
    // link to the private key to an external service for key wrapping and release.
    // Here we just wrap a pre-defined RSA key using import key and return it.
    status = mock_key_wrap_and_release(keyType,
        attestationToken,
        linkToPrivateKey,
        importKey,
        &bufferKeyBlob,
        &bufferKeyBlobSize);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to mock key wrap and release. "
            "mock_key_wrap_and_release returned: 0x%08x\n",
            status);
        goto cleanup;
    }

    printf("\nStep 4: Import Wrapped Key"
        "\n--------------------------\n");
    status = import_wrapped_key(keyType,
        provider,
        importKey,
        bufferKeyBlob,
        bufferKeyBlobSize,
        NCRYPT_ALLOW_SIGNING_FLAG,
        &importedKey);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to import key. "
            "import_wrapped_key returned: 0x%08x\n",
            status);
        goto cleanup;
    }

    printf("\nStep 5: Sign with imported key and Verify"
        "\n-----------------------------------------\n");
    if (keyType == KeyType::KEY_TYPE_RSA) {
        status = sign_verify_rsa(importedKey, hashSizeRsa, hashAlgId, &bufferSignature, &bufferSignatureSize);
    }
    else {
        status = sign_verify_ecdsa(importedKey, hashSizeEcdsa, &bufferSignature, &bufferSignatureSize);
    }
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to sign and verify. "
            "sign_verify returned: 0x%08x\n",
            status);
        goto cleanup;
    }

    // Verify with pre-calculated signature for RSA Signing
    if (keyType == KeyType::KEY_TYPE_RSA) {
        if (bufferSignatureSize != sizeof(EXPECTED_SIGNATURE_RSA) ||
            memcmp(bufferSignature, EXPECTED_SIGNATURE_RSA, sizeof(EXPECTED_SIGNATURE_RSA)) != 0)
        {
            fprintf(stderr, "Signature verification failed. Expected signature does not match the actual signature.\n");
            status = E_FAIL;
            goto cleanup;
        }
        printf("Signature matches pre-calculated value\n");
    }

    printf("\nSample finished successfully"
        "\n----------------------------\n");

    status = S_OK;
cleanup:
    if (bufferSignature)
    {
        delete[] bufferSignature;
    }

    if (bufferKeyBlob)
    {
        delete[] bufferKeyBlob;
    }

    if (bufferCollateral)
    {
        delete[] bufferCollateral;
    }

    if (bufferQuote)
    {
        delete[] bufferQuote;
    }

    if (importedKey)
    {
        NCryptFreeObject(importedKey);
    }

    if (importKey)
    {
        NCryptFreeObject(importKey);
    }

    if (provider)
    {
        NCryptFreeObject(provider);
    }

    printf("\nDone Cleaning Up"
        "\n----------------\n");

    return status;
}
