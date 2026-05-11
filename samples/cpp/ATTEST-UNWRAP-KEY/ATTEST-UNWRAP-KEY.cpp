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

#include <iostream>
#include <cstdio>
#include <string>

#include <windows.h>
#include <ncrypt.h>

#include <wil/resource.h>
#include <wil/result.h>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"
#include "Utils/RsaWrapUtils.h"
#include "Utils/CryptoUtils.h"

#include "RsaKey.h"
#include "EcdsaKey.h"

// Fetch quote and Collateral from AziHSM
// Quote and Collateral will be in a opaque format
HRESULT get_quote_and_certificate(
    _In_ const NCRYPT_PROV_HANDLE &provider,
    _In_ const NCRYPT_KEY_HANDLE &importKey,
    _In_reads_(128) const char userdata[128],
    _Out_ std::vector<BYTE> &outBufferQuote,
    _Out_ std::vector<BYTE> &outBufferCertificate)
{
    UNREFERENCED_PARAMETER(provider);
    RETURN_HR_IF_MSG(E_INVALIDARG, importKey == 0, "Invalid import key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, userdata == nullptr, "User data buffer must not be null");

    // A fixed-size (128 bytes) buffer that will be copied into the quote
    // This buffer is used to provide a nonce for the quote generation.
    NCryptBuffer bcryptBuffer = {128, NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, (PVOID)userdata};
    NCryptBufferDesc paramBuffers = {NCRYPTBUFFER_VERSION, 1, &bcryptBuffer};

    // Use NCryptCreateClaim to obtain the unwrapping key attestation report + certificate chain
    // Get size of the output buffer
    DWORD bytes = 0;

    RETURN_IF_FAILED_MSG(NCryptCreateClaim(importKey, NULL, AZIHSM_CLAIM_TYPE_KEY_ATTESTATION, &paramBuffers, NULL, 0, &bytes, 0), "Failed 1st NCryptCreateClaim");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0, "Claim size must be non-zero");

    // Create buffer to receive data
    std::vector<BYTE> bufferClaim(bytes);

    // Get quote and certificate
    RETURN_IF_FAILED_MSG(NCryptCreateClaim(importKey, NULL, AZIHSM_CLAIM_TYPE_KEY_ATTESTATION, &paramBuffers, bufferClaim.data(), (DWORD)bufferClaim.size(), &bytes, 0), "Failed 2nd NCryptCreateClaim");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0 || bytes > bufferClaim.size(), "Unexpected claim size: %u", bytes);

    // The pre-allocated buffer size may be larger than the actual quote size, so we update the size
    bufferClaim.resize(bytes);

    // Offset in bufferClaim
    // Quote == bufferClaim[bufferQuoteOffset, bufferQuoteOffset + bufferQuoteSize]
    DWORD bufferQuoteOffset = 0;
    DWORD bufferQuoteSize = 0;

    // Offset to bufferClaim
    // Certificate == bufferClaim[bufferCertificateOffset, bufferCertificateOffset + bufferCertificateSize]
    DWORD bufferCertificateOffset = 0;
    DWORD bufferCertificateSize = 0;

    AZIHSM_STATUS azihsm_status = azihsm_parse_claim(bufferClaim.data(), (DWORD)bufferClaim.size(),
                                                     &bufferQuoteOffset, &bufferQuoteSize,
                                                     &bufferCertificateOffset, &bufferCertificateSize);

    RETURN_HR_IF_MSG(E_FAIL, AZIHSM_STATUS::AZIHSM_SUCCESS != azihsm_status, "Failed to parse claim buffer, status: %d", (int)azihsm_status);
    RETURN_HR_IF_MSG(E_UNEXPECTED, bufferQuoteSize == 0, "Quote size must be non-zero");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bufferCertificateSize == 0, "Certificate size must be non-zero");
    RETURN_HR_IF_MSG(E_UNEXPECTED,
                     (size_t)bufferQuoteOffset + (size_t)bufferQuoteSize > bufferClaim.size(),
                     "Quote buffer bounds are invalid");
    RETURN_HR_IF_MSG(E_UNEXPECTED,
                     (size_t)bufferCertificateOffset + (size_t)bufferCertificateSize > bufferClaim.size(),
                     "Certificate buffer bounds are invalid");

    // Return copy of quote + certificate so we can free the buffer returned from NCryptCreateClaim
    outBufferQuote = std::vector<BYTE>(bufferClaim.begin() + bufferQuoteOffset, bufferClaim.begin() + bufferQuoteOffset + bufferQuoteSize);
    outBufferCertificate = std::vector<BYTE>(bufferClaim.begin() + bufferCertificateOffset, bufferClaim.begin() + bufferCertificateOffset + bufferCertificateSize);

    return S_OK;
}

// You should not care about the implementation of this function
// As it mocks the behavior of an external service that
// 1. Verifies the quote and collateral
// 2. Returns an attestation token
HRESULT mock_attestation(
    _In_ const std::vector<BYTE> &bufferQuote,
    _In_ const std::vector<BYTE> &bufferCollateral,
    _Out_ int &outToken)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, bufferQuote.empty(), "Quote buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, bufferCollateral.empty(), "Collateral buffer must not be empty");

    // Dump quote and collateral size
    printf("Quote: %zu bytes. Collateral: %zu bytes.\n", bufferQuote.size(), bufferCollateral.size());

    // Skip actual attestation or verification of the quote and collateral
    // Return a mock attestation token, this typically is a JWT
    // Using a number here for simplicity
    outToken = 123;

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
HRESULT mock_key_wrap_and_release(
    _In_ const KeyType keyType,
    _In_ const int attestationToken,
    _In_ const std::string &linkToPrivateKey,
    _In_ const NCRYPT_KEY_HANDLE &importKey,
    _Out_ std::vector<BYTE> &outBufferKeyBlob)
{
    // Mock verification
    LOG_HR_IF_MSG(NTE_BAD_DATA, attestationToken == 0, "Invalid attestation token: %d", attestationToken);
    LOG_HR_IF_MSG(NTE_BAD_DATA, linkToPrivateKey.empty(), "Invalid link to private key");
    RETURN_HR_IF_MSG(E_INVALIDARG, importKey == 0, "Invalid import key handle");

    // The hash algorithm ID during key wrap
    // All options:
    // NCRYPT_SHA1_ALGORITHM
    // NCRYPT_SHA256_ALGORITHM
    // NCRYPT_SHA384_ALGORITHM
    // NCRYPT_SHA512_ALGORITHM
    LPCWSTR hashAlgId = NCRYPT_SHA256_ALGORITHM;

    // Buffer to hold the Private Key (DER format) to be imported
    std::vector<BYTE> bufferToBeImportedKey;

    // For this sample, use a pre-generated private key
    if (keyType == KeyType::KEY_TYPE_RSA)
    {
        bufferToBeImportedKey = std::vector<BYTE>(PRIVATE_KEY_RSA, PRIVATE_KEY_RSA + sizeof(PRIVATE_KEY_RSA));
    }
    else
    {
        bufferToBeImportedKey = std::vector<BYTE>(PRIVATE_KEY_ECDSA, PRIVATE_KEY_ECDSA + sizeof(PRIVATE_KEY_ECDSA));
    }

    // Get buffer size
    DWORD bytes = 0;
    RETURN_IF_FAILED_MSG(NCryptExportKey(importKey,
                                         NULL,
                                         BCRYPT_RSAPUBLIC_BLOB,
                                         NULL,
                                         NULL,
                                         0,
                                         &bytes,
                                         0),
                         "Failed 1st NCryptExportKey");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0, "Import key public blob size must be non-zero");

    // Prepare buffer to receive Public key of Import Key in BCrypt format
    std::vector<BYTE> bufferImportKey(bytes);

    // Get Public Key of Import Key
    RETURN_IF_FAILED_MSG(NCryptExportKey(importKey,
                                         NULL,
                                         BCRYPT_RSAPUBLIC_BLOB,
                                         NULL,
                                         bufferImportKey.data(),
                                         (DWORD)bufferImportKey.size(),
                                         &bytes,
                                         0),
                         "Failed 2nd NCryptExportKey");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0 || bytes > bufferImportKey.size(), "Unexpected import key public blob size: %u", bytes);
    // The pre-allocated buffer might exceeds actual size, always update the size
    bufferImportKey.resize(bytes);

    // Wrap and export private Key
    RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(WrapKey(bufferToBeImportedKey.data(),
                                                 (DWORD)bufferToBeImportedKey.size(),
                                                 bufferImportKey.data(),
                                                 (DWORD)bufferImportKey.size(),
                                                 hashAlgId,
                                                 outBufferKeyBlob)),
                         "Failed ExportKeyWrapped");
    RETURN_HR_IF_MSG(E_UNEXPECTED, outBufferKeyBlob.empty(), "Wrapped key blob must not be empty");

    return S_OK;
}

int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    try
    {
        set_wil_log_callback();

        printf("\n\nAziHSM Demonstration:\nGet Quote/Collateral --> Mock Attestation --> Mock Key Wrap and Release --> Import "
               "--> Sign/Verify\n");
        printf("==================================================================================================\n");

        // Import the RSA or ECDSA key in this sample?
        // Default to RSA
        const char *argKeyType = (argc > 1) ? argv[1] : nullptr;
        KeyType keyType = KeyType::KEY_TYPE_RSA;

        if (argKeyType != nullptr)
        {
            parse_key_type(argKeyType, keyType);
        }

        if (keyType == KeyType::KEY_TYPE_RSA)
        {
            printf("\nWorking with RSA key.\n");
        }
        else
        {
            printf("\nWorking with ECDSA key.\n");
        }

        // A buffer to be copied into the AziHSM quote
        // This should be a unique value like hash of some other stuff
        // So user knows the quote is freshly generated for them
        char userdata[128] = "Put your custom data here to be included in the quote. For example hash";

        printf("\nStep 1: Get Quote and Collateral"
               "\n--------------------------------\n");

        // AziHSM Provider
        wil::unique_ncrypt_prov provider;
        // AziHSM Builtin Import Key
        wil::unique_ncrypt_key importKey;

        RETURN_IF_FAILED_MSG(open_provider_and_key(provider, importKey), "Failed open_provider_and_key");

        // quote from AziHSM
        std::vector<BYTE> bufferQuote;
        // collateral from AziHSM, it contains certificate chain
        std::vector<BYTE> bufferCollateral;

        RETURN_IF_FAILED_MSG(get_quote_and_certificate(
                                 provider.get(),
                                 importKey.get(),
                                 userdata,
                                 bufferQuote,
                                 bufferCollateral),
                             "Failed get_quote_and_certificate");

        printf("\nStep 2: Mock Attestation"
               "\n------------------------\n");

        // (Mocked) Attestation Token
        // Usually should be a JWT
        int attestationToken = 0;

        // In a real-world scenario, you would send the quote and collateral to
        // an external service for attestation verification.
        // Here we just dump the quote and collateral and return a mock attestation token.
        RETURN_IF_FAILED_MSG(mock_attestation(bufferQuote, bufferCollateral, attestationToken), "Failed mock_attestation");

        printf("\nStep 3: Mock Key Wrap and Release"
               "\n---------------------------------\n");

        // (Mocked) Link to the private key user wishes to Secure Key Release and Import into AziHSM
        // In a real-world scenario, this would be a link to a private key stored in Azure Key Vault, for example.
        char linkToPrivateKey[256] = "http://link/to/private/key/you/wish/to/import";

        // In a real-world scenario, you would send the attestation token,
        // link to the private key to an external service for key wrapping and release.
        // Here we just wrap a pre-defined RSA key using import key and return it.
        std::vector<BYTE> bufferKeyBlob;

        RETURN_IF_FAILED_MSG(mock_key_wrap_and_release(keyType,
                                                       attestationToken,
                                                       linkToPrivateKey,
                                                       importKey.get(),
                                                       bufferKeyBlob),
                             "Failed mock_key_wrap_and_release");
        RETURN_HR_IF_MSG(E_UNEXPECTED, bufferKeyBlob.empty(), "Wrapped key blob is empty");

        printf("\nStep 4: Import Wrapped Key"
               "\n--------------------------\n");

        // Handle to the imported RSA key
        wil::unique_ncrypt_key importedKey;

        RETURN_IF_FAILED_MSG(import_bcrypt_wrapped_key(
                                 provider.get(),
                                 importKey.get(),
                                 bufferKeyBlob.data(),
                                 (DWORD)bufferKeyBlob.size(),
                                 keyType,
                                 // In this sample, hardcoded RSA key is 2K in size, EC Key is P-256
                                 (keyType == KeyType::KEY_TYPE_RSA) ? 2048 : 256,
                                 NCRYPT_ALLOW_SIGNING_FLAG,
                                 importedKey),
                             "Failed import_bcrypt_wrapped_key");

        printf("\nStep 5: Sign with imported key and Verify"
               "\n-----------------------------------------\n");

        // Signature generated during Signing
        std::vector<BYTE> bufferSignature;

        if (keyType == KeyType::KEY_TYPE_RSA)
        {
            // For RSA signing
            // Pick the hash size and hash algorithm
            // This should be set according to Hash Algorithm
            // SHA256: 32
            // SHA384: 48
            // SHA512: 64
            DWORD hashSizeRsa = 32;
            LPCWSTR hashAlgId = BCRYPT_SHA256_ALGORITHM;

            RETURN_IF_FAILED_MSG(sign_verify_rsa(importedKey.get(), hashSizeRsa, hashAlgId, MESSAGE_RSA, bufferSignature), "Failed sign_verify_rsa");

            // Verify with pre-calculated signature for RSA Signing
            if (bufferSignature.size() != sizeof(EXPECTED_SIGNATURE_RSA) ||
                memcmp(bufferSignature.data(), EXPECTED_SIGNATURE_RSA, sizeof(EXPECTED_SIGNATURE_RSA)) != 0)
            {
                fprintf(stderr, "Signature verification failed. Expected signature does not match the actual signature.\n");
                return E_FAIL;
            }
            printf("Signature matches pre-calculated value\n");
        }
        else
        {
            // For ECDSA signing
            // Pick the hash size
            // This should be set according to ECC Key Curve Type
            // P256: 32
            // P384: 48
            // P521: 66
            // Using 32 here as the ECDSA key in this sample is P256
            DWORD hashSizeEcdsa = 32;

            RETURN_IF_FAILED_MSG(sign_verify_ecdsa(importedKey.get(), hashSizeEcdsa, MESSAGE_ECDSA, bufferSignature), "Failed sign_verify_ecdsa");
        }

        printf("\nSample finished successfully"
               "\n----------------------------\n");

        return S_OK;
    }
    catch (const std::exception &ex)
    {
        fprintf(stderr, "Unhandled exception in ATTEST-UNWRAP-KEY sample: %s\n", ex.what());
        return E_FAIL;
    }
    catch (...)
    {
        fprintf(stderr, "Unhandled unknown exception in ATTEST-UNWRAP-KEY sample\n");
        return E_FAIL;
    }
}
