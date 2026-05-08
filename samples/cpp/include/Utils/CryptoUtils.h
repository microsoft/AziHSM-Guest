// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header file defines common crypto operations that uses NCrypt API

#pragma once

#include "Utils.h"

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#include <wil/resource.h>
#include <wil/result.h>

enum class KeyType {
    KEY_TYPE_RSA,
    KEY_TYPE_ECDSA
};

// Parse into KeyType, case insensitive
inline HRESULT parse_key_type(
    const std::string& in,
    KeyType& outType)
{
    std::string keyType = in;
    std::transform(keyType.begin(), keyType.end(), keyType.begin(), ::tolower);

    if (keyType == "rsa")
    {
        outType = KeyType::KEY_TYPE_RSA;
    }
    else if (keyType == "ecdsa")
    {
        outType = KeyType::KEY_TYPE_ECDSA;
    }
    else
    {
        std::cerr << "Invalid key type: " << in << ". Supported types: RSA, ECDSA" << std::endl;
        return E_INVALIDARG;
    }

    return S_OK;
}

// Call NCrypt API to open AziHSM provider
// Then obtain the built-in import/wrapping key of AziHSM provider
//
// outHProvider: The handle to the opened AZIHSM provider
// outHImportKey: The handle to the built-in import/wrapping key in AZIHSM
inline HRESULT open_provider_and_key(
    wil::unique_ncrypt_prov& outHProvider,
    wil::unique_ncrypt_key& outHImportKey)
{
    wil::unique_ncrypt_prov hProvider;
    wil::unique_ncrypt_key hImportKey;

    // Open the AziHSM KSP provider
    RETURN_IF_FAILED_MSG(NCryptOpenStorageProvider(
        hProvider.put(),
        AZIHSM_KSP_NAME,
        0),
        "Failed NCryptOpenStorageProvider");

    // Open the built-in unwrapping key from the provider
    RETURN_IF_FAILED_MSG(NCryptOpenKey(
        hProvider.get(),
        hImportKey.put(),
        AZIHSM_BUILTIN_UNWRAP_KEY_NAME,
        0,
        0),
        "Failed NCryptOpenKey");

    outHProvider = std::move(hProvider);
    outHImportKey = std::move(hImportKey);

    return S_OK;
}

// You can import a wrapped key presented by BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
// You also need to set key property during import
//
// bufferKeyBlob: a buffer containing BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
//
// keyType: RSA or ECDSA
//
// keySize: Ignored if keyType is RSA, its size will be deduced from bufferKeyBlob.
// Set key size for ECDSA, Can be one of: 256, 384, 521
//
// keyUsage: Ignored if keyType is ECDSA as they can only sign.
// Set usage for RSA key. Can be one of:
//     NCRYPT_ALLOW_DECRYPT_FLAG: Allow Encrypt/Decrypt
//     NCRYPT_ALLOW_SIGNING_FLAG: Allow Sign/Verify
//     NCRYPT_ALLOW_KEY_IMPORT_FLAG: Allow importing keys
inline HRESULT import_bcrypt_wrapped_key(
    const NCRYPT_PROV_HANDLE& provider,
    const NCRYPT_KEY_HANDLE& importKey,
    const PBYTE bufferKeyBlob,
    const DWORD bufferKeyBlobSize,
    const KeyType keyType,
    const int keySize,
    const DWORD keyUsage,
    wil::unique_ncrypt_key& outImportedKey)
{
    wil::unique_ncrypt_key importedKey;

    // Pick the algorithm same as the type of key you wish to import
    LPCWSTR algo = nullptr;
    if (keyType == KeyType::KEY_TYPE_RSA) {
        algo = BCRYPT_RSA_ALGORITHM;
    }
    else {
        if (keySize == 256) {
            algo = BCRYPT_ECDSA_P256_ALGORITHM;
        }
        else if (keySize == 384) {
            algo = BCRYPT_ECDSA_P384_ALGORITHM;
        }
        else if (keySize == 521) {
            algo = BCRYPT_ECDSA_P521_ALGORITHM;
        }
        else {
            RETURN_HR_MSG(E_INVALIDARG, "Invalid Key Size for ECDSA key: %d", keySize);
        }
    }

    // Count the number of bytes in the algorithm ID string.
    size_t algo_len = 0;
    RETURN_IF_FAILED_MSG(count_wide_string_bytes(algo, &algo_len), "Failed count_wide_string_bytes");

    // Set up NCrypt buffer objects.
    const size_t paramBuffersLen = 1;
    NCryptBuffer paramBuffers[paramBuffersLen];

    paramBuffers[0].BufferType = NCRYPTBUFFER_PKCS_ALG_ID;
    paramBuffers[0].pvBuffer = (PVOID)algo;
    paramBuffers[0].cbBuffer = (ULONG)algo_len;

    NCryptBufferDesc paramBuffer = { NCRYPTBUFFER_VERSION, 1, paramBuffers };

    // Import Key blob
    RETURN_IF_FAILED_MSG(NCryptImportKey(
        provider,
        importKey,
        BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
        &paramBuffer,
        importedKey.put(),
        bufferKeyBlob,
        bufferKeyBlobSize,
        NCRYPT_DO_NOT_FINALIZE_FLAG),
        "Failed NCryptImportKey");

    if (keyType == KeyType::KEY_TYPE_RSA) {
        // RSA key can be used for signing or encryption
        // We need to explictly set the usage
        // Here we want to use the imported RSA key for signing
        RETURN_IF_FAILED_MSG(NCryptSetProperty(
            importedKey.get(),
            NCRYPT_KEY_USAGE_PROPERTY,
            (PBYTE)&keyUsage,
            sizeof(keyUsage),
            0),
            "Failed NCryptSetProperty");

        // Optionally, we can set the RSA key to be CRT-enabled
        // This is an optimization that allows for faster RSA operations
        // At the cost of requiring more space to store the key
        RETURN_IF_FAILED_MSG(NCryptSetProperty(
            importedKey.get(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_NAME,
            (PBYTE)&AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED,
            sizeof(uint32_t),
            0),
            "Failed NCryptSetProperty for RSA CRT");
    }
    else {
        // No need to set usage for ECDSA key
    }

    RETURN_IF_FAILED_MSG(NCryptFinalizeKey(importedKey.get(), 0), "Failed NCryptFinalizeKey");

    outImportedKey = std::move(importedKey);

    return S_OK;
}

// Use the imported key to sign something and verify
// Use RSA Key
inline HRESULT sign_verify_rsa(
    const NCRYPT_KEY_HANDLE& importedKey,
    DWORD bufferHashSize,
    LPCWSTR hashAlgId,
    const std::string& message,
    std::vector<BYTE>& outSig)
{
    RETURN_HR_IF(E_INVALIDARG, message.length() > bufferHashSize);
    std::vector<BYTE> bufferHash(bufferHashSize);
    memcpy(bufferHash.data(), message.data(), message.length());

    // For padding, we can either use
    DWORD flagPadding = NCRYPT_PAD_PKCS1_FLAG;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { hashAlgId };

    // Or
    // DWORD flagPadding = NCRYPT_PAD_PSS_FLAG;
    // BCRYPT_PSS_PADDING_INFO paddingInfo = { hashAlgId , <random number less than bufferHashSize>};

    DWORD bytes = 0;

    RETURN_IF_FAILED_MSG(NCryptSignHash(
        importedKey,
        &paddingInfo,
        bufferHash.data(),
        (DWORD)bufferHash.size(),
        NULL,
        0,
        &bytes,
        flagPadding),
        "Failed 1st NCryptSignHash");

    std::vector<BYTE> bufferSignature(bytes);
    RETURN_IF_FAILED_MSG(NCryptSignHash(
        importedKey,
        &paddingInfo,
        bufferHash.data(),
        (DWORD)bufferHash.size(),
        bufferSignature.data(),
        (DWORD)bufferSignature.size(),
        &bytes,
        flagPadding),
        "Failed 2nd NCryptSignHash");

    printf("Signature size: %lu bytes.\n", bytes);
    bufferSignature.resize(bytes);

    // Verify itself
    RETURN_IF_FAILED_MSG(NCryptVerifySignature(
        importedKey,
        &paddingInfo,
        bufferHash.data(),
        (DWORD)bufferHash.size(),
        bufferSignature.data(),
        (DWORD)bufferSignature.size(),
        flagPadding),
        "Failed RSA NCryptVerifySignature");
    printf("Signature internally verified successfully.\n");

    outSig = std::move(bufferSignature);

    return S_OK;
}

// Use the imported key to sign something and verify
// Use ECDSA Key
// The signature is in raw format (r s), not ASN.1 encoded
inline HRESULT sign_verify_ecdsa(
    const NCRYPT_KEY_HANDLE& importedKey,
    DWORD bufferHashSize,
    const std::string& message,
    std::vector<BYTE>& outSig)
{
    RETURN_HR_IF(E_INVALIDARG, message.length() > bufferHashSize);
    std::vector<BYTE> bufferHash(bufferHashSize);
    memcpy(bufferHash.data(), message.data(), message.length());

    DWORD bytes = 0;

    RETURN_IF_FAILED_MSG(NCryptSignHash(
        importedKey,
        NULL,
        bufferHash.data(),
        (DWORD)bufferHash.size(),
        NULL,
        0,
        &bytes,
        0),
        "Failed 1st NCryptSignHash");

    DWORD bufferSignatureSize = bytes;
    std::vector<BYTE> bufferSignature(bufferSignatureSize);
    RETURN_IF_FAILED_MSG(NCryptSignHash(
        importedKey,
        NULL,
        bufferHash.data(),
        (DWORD)bufferHash.size(),
        bufferSignature.data(),
        (DWORD)bufferSignature.size(),
        &bytes,
        0),
        "Failed 2nd NCryptSignHash");
    printf("Signature size: %lu bytes.\n", bytes);
    bufferSignatureSize = bytes;
    bufferSignature.resize(bufferSignatureSize);

    // Verify itself
    RETURN_IF_FAILED_MSG(NCryptVerifySignature(
        importedKey,
        NULL,
        bufferHash.data(),
        (DWORD)bufferHash.size(),
        bufferSignature.data(),
        (DWORD)bufferSignature.size(),
        0),
        "Failed ECDSA NCryptVerifySignature");
    printf("Signature internally verified successfully.\n");

    outSig = std::move(bufferSignature);

    return S_OK;
}

// Use the imported key to encrypt/decrypt and verify
// Use RSA Key
inline HRESULT encrypt_decrypt_rsa(
    const NCRYPT_KEY_HANDLE& hImportedKey,
    LPCWSTR hashAlgId,
    const std::string& message
) {
    // For example, use hash algorithm without label
    BCRYPT_OAEP_PADDING_INFO padding_info = {
        hashAlgId, nullptr, 0,
    };

    /*
    There are other configuration for encrypt using RSA

    1. OAEP With label

    BCRYPT_OAEP_PADDING_INFO padding_info = {
        hashAlgId, L"Some label", count_wide_string_bytes(label),
    };
    */

    std::vector<BYTE> buffer(message.size());
    memcpy(buffer.data(), message.data(), message.length());

    // Get the required buffer size for encryption
    DWORD bytes = 0;
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
        hImportedKey,
        buffer.data(),
        (DWORD)buffer.size(),
        &padding_info,
        nullptr, // output buffer (null to get size)
        0,       // output buffer size
        &bytes,
        NCRYPT_PAD_OAEP_FLAG),
        "Failed 1st NCryptEncrypt");

    // Allocate buffer for ciphertext
    std::vector<BYTE> ciphertext(bytes);

    // Perform encryption
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
        hImportedKey,
        buffer.data(),
        (DWORD)buffer.size(),
        &padding_info,
        ciphertext.data(),
        (DWORD)ciphertext.size(),
        &bytes,
        NCRYPT_PAD_OAEP_FLAG),
        "Failed 2nd NCryptEncrypt");

    ciphertext.resize(bytes);

    std::cout << "Encryption successful. Ciphertext length: " << bytes << std::endl;

    // Get the required buffer size for decryption
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
        hImportedKey,
        ciphertext.data(),
        (DWORD)ciphertext.size(),
        &padding_info,
        nullptr, // output buffer (null to get size)
        0,       // output buffer size
        &bytes,
        NCRYPT_PAD_OAEP_FLAG),
        "Failed 1st NCryptDecrypt");

    // Allocate buffer for decrypted text
    std::vector<BYTE> decryptedText(bytes);

    // Perform decryption
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
        hImportedKey,
        ciphertext.data(),
        (DWORD)ciphertext.size(),
        &padding_info,
        decryptedText.data(),
        (DWORD)decryptedText.size(),
        &bytes,
        NCRYPT_PAD_OAEP_FLAG),
        "Failed 2nd NCryptDecrypt");
    std::cout << "Decryption successful. Decrypted Text length: " << bytes << std::endl;
    decryptedText.resize(bytes);

    // Verify the decrypted data matches the original
    if (decryptedText.size() != message.size() ||
        memcmp(decryptedText.data(), message.data(), message.size()) != 0)
    {
        std::cerr << "Decrypted data does not match original plaintext" << std::endl;
        return E_UNEXPECTED;
    }

    std::cout << "Encrypt-decrypt test passed!" << std::endl;

    return S_OK;
}

// Encrypt using AES Key with GCM Mode
// outIv should have size AZIHSM_AES_GCM_IV_LENGTH_BYTES and populated with all ZERO
inline HRESULT encrypt_aes_gcm(const NCRYPT_KEY_HANDLE& key,
    const std::vector<BYTE>& plaintext,
    const std::vector<BYTE>& aad,
    std::vector<BYTE>& outIv,
    std::vector<BYTE>& outTag,
    std::vector<BYTE>& outResult)
{
    // -------------------------- Parameter Setup --------------------------- //
    // Before calling `NCryptEncrypt`, we need to set up parameter objects that
    // contain information needed by the AES-GCM algorithm.
    //
    // Some of these have already been provided to us in the function
    // parameters (`iv`, `aad`), but we need to pack them into a buffer that
    // NCrypt can understand.

    // Start by retrieving the tag length from the key properties. This will
    // return a `BCRYPT_KEY_LENGTHS_STRUCT` object, which contains the tag
    // length.
    BCRYPT_KEY_LENGTHS_STRUCT tag_len_obj;
    DWORD bytes = 0;
    RETURN_IF_FAILED_MSG(NCryptGetProperty(
        key,
        BCRYPT_AUTH_TAG_LENGTH,
        (PBYTE)&tag_len_obj,
        (DWORD)sizeof(BCRYPT_KEY_LENGTHS_STRUCT),
        &bytes,
        0
    ), "Failed NCryptGetProperty BCRYPT_AUTH_TAG_LENGTH");

    // The AziHSM KSP only supports a fixed tag length, even though the
    // `BCRYPT_KEY_LENGTHS_STRUCT` structure allows for a range of valid tag
    // lengths. Because of this, the `dwMinLength` and `dwMaxLength` fields
    // will both be set to the fixed tag length supported by the device, and
    // the `dwIncrement` field will be set to 0.

    // With the tag length, allocate a buffer to hold the tag. (This buffer
    // will be filled by the AziHSM during encryption.)
    std::vector<BYTE> tag(tag_len_obj.dwMinLength);

    // Next, set up a `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure to hold
    // the AES-GCM parameters.
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi;
    BCRYPT_INIT_AUTH_MODE_INFO(acmi);
    acmi.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
    acmi.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    acmi.dwFlags = 0;
    acmi.pbNonce = (PUCHAR)outIv.data();
    acmi.cbNonce = (ULONG)outIv.size();
    acmi.pbAuthData = (PUCHAR)aad.data();
    acmi.cbAuthData = (ULONG)aad.size();
    acmi.pbTag = tag.data();
    acmi.cbTag = (ULONG)tag.size();

    // Create a `NCRYPT_CIPHER_PADDING_INFO` struct to hold the above
    // structure; this is the primary object we pass into `NCryptEncrypt`.
    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.dwFlags = NCRYPT_CIPHER_OTHER_PADDING_FLAG; // <-- Indicates that `acmi` is present.
    pinfo.pbIV = NULL; // <-- IV is provided in `acmi`, so set to NULL here.
    pinfo.cbIV = 0;    // <-- IV is provided in `acmi`, so set to 0 here.
    pinfo.pbOtherInfo = (PBYTE)&acmi;
    pinfo.cbOtherInfo = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);

    // ----------------------- Performing Encryption ------------------------ //
    // Call `NCryptEncrypt` once, to determine how many bytes are needed to
    // store the ciphertext.
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
        key,
        (PBYTE)plaintext.data(),
        (DWORD)plaintext.size(),
        &pinfo,
        NULL,
        0,
        &bytes,
        NCRYPT_PAD_CIPHER_FLAG
    ), "Failed 1st NCryptEncrypt");

    // Allocate a buffer to store the ciphertext, then call `NCryptEncrypt` a
    // second time to generate it and store the result.
    std::vector<BYTE> ciphertext(bytes);
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
        key,
        (PBYTE)plaintext.data(),
        (DWORD)plaintext.size(),
        &pinfo,
        ciphertext.data(),
        (DWORD)ciphertext.size(),
        &bytes,
        NCRYPT_PAD_CIPHER_FLAG
    ), "Failed 2nd NCryptEncrypt");

    outTag = std::move(tag);
    outResult = std::move(ciphertext);

    return S_OK;
}

// Decrypt using AES Key with GCM Mode
inline HRESULT decrypt_aes_gcm(const NCRYPT_KEY_HANDLE& key,
    const std::vector<BYTE>& ciphertext,
    const std::vector<BYTE>& aad,
    const std::vector<BYTE>& iv,
    const std::vector<BYTE>& tag,
    std::vector<BYTE>& outResult)
{
    // -------------------------- Parameter Setup --------------------------- //
    // First, set up a `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure to
    // hold the AES-GCM parameters.
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi;
    BCRYPT_INIT_AUTH_MODE_INFO(acmi);
    acmi.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
    acmi.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    acmi.dwFlags = 0;
    acmi.pbNonce = (PUCHAR)iv.data();
    acmi.cbNonce = (ULONG)iv.size();
    acmi.pbAuthData = (PUCHAR)aad.data();
    acmi.cbAuthData = (ULONG)aad.size();
    acmi.pbTag = (PUCHAR)tag.data();
    acmi.cbTag = (ULONG)tag.size();

    // Create a `NCRYPT_CIPHER_PADDING_INFO` struct to hold the above
    // structure; this is the primary object we pass into `NCryptDecrypt`.
    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.dwFlags = NCRYPT_CIPHER_OTHER_PADDING_FLAG; // <-- Indicates that `acmi` is present.
    pinfo.pbIV = NULL; // <-- IV is provided in `acmi`, so set to NULL here.
    pinfo.cbIV = 0;    // <-- IV is provided in `acmi`, so set to 0 here.
    pinfo.pbOtherInfo = (PBYTE)&acmi;
    pinfo.cbOtherInfo = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);

    // ----------------------- Performing Decryption ------------------------ //
    // Call `NCryptDecrypt` once, to determine how many bytes are needed to
    // store the plaintext.
    DWORD bytes;
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
        key,
        (PBYTE)ciphertext.data(),
        (DWORD)ciphertext.size(),
        &pinfo,
        NULL,
        0,
        &bytes,
        NCRYPT_PAD_CIPHER_FLAG
    ), "Failed 1st NCryptDecrypt");

    // Allocate a buffer to store the plaintext, then call `NCryptDecrypt` a
    // second time to generate it and store the result.
    std::vector<BYTE> decrypted(bytes);
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
        key,
        (PBYTE)ciphertext.data(),
        (DWORD)ciphertext.size(),
        &pinfo,
        decrypted.data(),
        (DWORD)decrypted.size(),
        &bytes,
        NCRYPT_PAD_CIPHER_FLAG
    ), "Failed 2nd NCryptDecrypt");

    outResult = std::move(decrypted);

    return S_OK;
}
