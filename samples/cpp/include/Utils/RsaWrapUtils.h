// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header file defines helper functions related to
// Exports a RSA key in the PKCS#11 format
// As a user of AziHSM, you should not care about the detail of these functions.

#pragma once

// Use `WIN32_NO_STATUS` to prevent macro-redefinition warnings in `ntstatus.h`
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>

#include <cstdio>

#define AES_KEY_WRAP_PAD_IV 0xA65959A6 // KWP
#define AES_KEY_WRAP_PAD_AES_BLOCK_LENGTH 16
#define AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH 8

// 256 is the only supported AES bit size for Key Wrap
const DWORD AES_KEY_BIT_SIZE = 256;

// Helper function to create random AES key in BCrypt.
static NTSTATUS CreateAesKey(BCRYPT_KEY_HANDLE* outAesKey, PBYTE* outBufferAesKey, DWORD* outBufferAesKeySize)
{
    NTSTATUS status = STATUS_SUCCESS;

    BCRYPT_ALG_HANDLE aesAlgo = NULL;
    BCRYPT_ALG_HANDLE aesKey = NULL;

    // Convert bit to byte
    DWORD bufferSize = AES_KEY_BIT_SIZE / 8;
    PBYTE buffer = new BYTE[bufferSize];

    status = BCryptOpenAlgorithmProvider(&aesAlgo, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Failed to open AES algorithm provider. BCryptOpenAlgorithmProvider returned: 0x%08X\n",
            status);
        goto cleanup;
    }

    status = BCryptGenRandom(NULL, buffer, bufferSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Failed to generate random AES buffer. BCryptGenRandom returned: 0x%08X\n", status);
        goto cleanup;
    }

    status = BCryptGenerateSymmetricKey(aesAlgo, &aesKey, NULL, 0, buffer, bufferSize, 0);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Failed to generate AES key. BCryptGenerateSymmetricKey returned: 0x%08X\n", status);
        goto cleanup;
    }

    *outAesKey = aesKey;
    aesKey = NULL;
    *outBufferAesKey = buffer;
    buffer = NULL;
    *outBufferAesKeySize = bufferSize;

    status = STATUS_SUCCESS;
cleanup:
    if (buffer)
    {
        delete[] buffer;
    }
    if (aesKey)
    {
        BCryptDestroyKey(aesKey);
    }
    if (aesAlgo)
    {
        BCryptCloseAlgorithmProvider(aesAlgo, 0);
    }
    return status;
}

// Helper function to load and create RSA Export Key in BCrypt.
static NTSTATUS CreateRsaExportKey(PBYTE bufferRsaExportKeyBin,
    DWORD bufferRsaExportKeyBinSize,
    BCRYPT_KEY_HANDLE* outRsaExportKey)
{
    NTSTATUS status = STATUS_SUCCESS;

    BCRYPT_ALG_HANDLE rsaAlgo = NULL;
    BCRYPT_ALG_HANDLE rsaKey = NULL;

    status = BCryptOpenAlgorithmProvider(&rsaAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Failed to open RSA algorithm provider. BCryptOpenAlgorithmProvider returned: 0x%08X\n",
            status);
        goto cleanup;
    }

    status = BCryptImportKeyPair(rsaAlgo,
        NULL,
        BCRYPT_PUBLIC_KEY_BLOB,
        &rsaKey,
        bufferRsaExportKeyBin,
        bufferRsaExportKeyBinSize,
        0);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Failed to import the RSA Export Key. BCryptImportKeyPair returned: 0x%08X\n", status);
        goto cleanup;
    }

    *outRsaExportKey = rsaKey;
    rsaKey = NULL;
    status = STATUS_SUCCESS;
cleanup:
    if (rsaKey)
    {
        BCryptDestroyKey(rsaKey);
    }
    if (rsaAlgo)
    {
        BCryptCloseAlgorithmProvider(rsaAlgo, 0);
    }
    return status;
}

// Helper function to encrypt AES key with RSA Export Key in BCrypt.
static NTSTATUS EncryptAesWithRsaExportKey(PBYTE bufferAesKey,
    DWORD bufferAesKeySize,
    BCRYPT_KEY_HANDLE rsaExportKey,
    LPCWSTR algId,
    PBYTE* outBuffer,
    DWORD* outBufferSize)
{
    NTSTATUS status = STATUS_SUCCESS;

    DWORD bytes = 0;
    PBYTE bufferEncrypted = NULL;
    DWORD bufferEncryptedSize = 0;

    BCRYPT_OAEP_PADDING_INFO oaepPadding = { 0 };
    oaepPadding.pszAlgId = algId;

    status = BCryptEncrypt(rsaExportKey,
        bufferAesKey,
        bufferAesKeySize,
        &oaepPadding,
        NULL,
        0,
        NULL,
        0,
        &bytes,
        BCRYPT_PAD_OAEP);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr,
            "Failed to get output size when encrypting AES buffer with RSA Export key. BCryptEncrypt returned: "
            "0x%08X\n",
            status);
        goto cleanup;
    }

    bufferEncrypted = new BYTE[bytes];
    bufferEncryptedSize = bytes;

    status = BCryptEncrypt(rsaExportKey,
        bufferAesKey,
        bufferAesKeySize,
        &oaepPadding,
        NULL,
        0,
        bufferEncrypted,
        bufferEncryptedSize,
        &bytes,
        BCRYPT_PAD_OAEP);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Failed to encrypt AES buffer with RSA Export key. BCryptEncrypt returned: 0x%08X\n", status);
        goto cleanup;
    }
    bufferEncryptedSize = bytes;

    *outBuffer = bufferEncrypted;
    bufferEncrypted = NULL;
    *outBufferSize = bufferEncryptedSize;

    status = STATUS_SUCCESS;
cleanup:
    if (bufferEncrypted)
    {
        delete[] bufferEncrypted;
    }
    return status;
}

// Helper function to implement the "4.1. Extended Key Wrapping Process" in RFC 5649.
// This should only be used for this sample for demonstration purposes.
// Do not use this in production code.
// Please reference OpenSSL EVP_aes_256_wrap_pad
static NTSTATUS AesKeyWrapPad(BCRYPT_KEY_HANDLE hAesKey, PBYTE pbInput, ULONG cbInput, PBYTE pbOutput, ULONG* pcbOutput)
{
    NTSTATUS status = STATUS_SUCCESS;

    ULONG pad = (AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH - (cbInput % AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH)) %
        AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH;
    ULONG n = (cbInput + pad) / AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH;
    ULONG cbLen = (n + 1) * AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH;

    if (pbOutput == NULL)
    {
        *pcbOutput = cbLen;
        return status;
    }

    ULONG cbR = cbLen - AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH;
    PBYTE pbR = new BYTE[cbR];

    BYTE rgbZero[AES_KEY_WRAP_PAD_AES_BLOCK_LENGTH] = { 0 };
    BYTE rgbBlock[AES_KEY_WRAP_PAD_AES_BLOCK_LENGTH * 2] = { 0 };
    BYTE rgbA[AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH] = { 0 };

    ULONG cbResult;

    ULONGLONG t;

    if (n == 1)
    {
        (*(ULONG*)pbR) = AES_KEY_WRAP_PAD_IV;
        (*(ULONG*)(pbR + sizeof(ULONG))) = _byteswap_ulong(cbInput);
        memcpy(pbR + AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH, pbInput, AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH);
        memset(rgbZero, 0, sizeof(rgbZero)); // zero out the IV so if we have an ECB/CBC key we do ECB
        status = BCryptEncrypt(hAesKey,
            rgbBlock,
            sizeof(rgbBlock),
            NULL,
            rgbZero,
            sizeof(rgbZero),
            pbR,
            cbLen,
            &cbResult,
            0);
        if (FAILED(HRESULT_FROM_NT(status)))
        {
            fprintf(stderr, "Error during AesKeyWrapPad n == 0. BCryptEncrypt returned: 0x%08X\n", status);
            goto cleanup;
        }
    }
    else
    {
        // Initialize variables
        // Set A = IV, an initial val
        (*(ULONG*)rgbA) = AES_KEY_WRAP_PAD_IV;
        (*(ULONG*)(rgbA + sizeof(ULONG))) = _byteswap_ulong(cbInput);
        memcpy(pbR, pbInput, cbInput);
        memset(pbR + cbInput, 0, pad);

        for (int j = 0; j < 6; j++)
        {
            for (ULONG i = 1; i <= n; i++)
            {
                (*(ULONGLONG*)rgbBlock) = (*(ULONGLONG*)rgbA);
                memcpy(rgbBlock + sizeof(rgbA), (pbR + AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH * (i - 1)), sizeof(rgbA));
                memset(rgbZero, 0, sizeof(rgbZero)); // zero out the IV so if we have an ECB/CBC key we do ECB
                status = BCryptEncrypt(hAesKey,
                    rgbBlock,
                    sizeof(rgbBlock),
                    NULL,
                    rgbZero,
                    sizeof(rgbZero),
                    rgbBlock,
                    sizeof(rgbBlock),
                    &cbResult,
                    0);
                if (FAILED(HRESULT_FROM_NT(status)))
                {
                    fprintf(stderr, "Error during AesKeyWrapPad n != 1. BCryptEncrypt returned: 0x%08X\n", status);
                    goto cleanup;
                }

                t = (n * j) + i;
                (*(ULONGLONG*)rgbA) = (*(ULONGLONG*)rgbBlock) ^ _byteswap_uint64(t);
                memcpy((pbR + AES_KEY_WRAP_PAD_TEXT_BLOCK_LENGTH * (i - 1)), rgbBlock + sizeof(rgbA), sizeof(rgbA));
            }
        }
    }

    memcpy(pbOutput, rgbA, sizeof(rgbA));
    memcpy(pbOutput + sizeof(rgbA), pbR, cbR); // Set the wrapped output buffer
    *pcbOutput = cbLen;                        // Set the output parameter length

cleanup:
    if (pbR)
    {
        delete[] pbR;
    }
    return status;
}

static void CreateBCryptStruct(PBYTE bufferEncryptedAesKey,
    DWORD bufferEncryptedAesKeySize,
    PBYTE bufferWrappedRsa,
    DWORD bufferWrappedRsaSize,
    LPCWSTR algId,
    PBYTE* out,
    DWORD* outSize)
{
    // Calculate the actual size of struct
    // Including string trailing zero
    ULONG algIdSize = (ULONG) ((wcslen(algId) + 1) * sizeof(wchar_t));
    DWORD structSize =
        sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + bufferEncryptedAesKeySize + bufferWrappedRsaSize + algIdSize;
    PBYTE buffer = new BYTE[structSize];

    PBCRYPT_PKCS11_RSA_AES_WRAP_BLOB blob = (PBCRYPT_PKCS11_RSA_AES_WRAP_BLOB)buffer;

    blob->dwMagic = BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC;
    blob->cbKey = bufferEncryptedAesKeySize + bufferWrappedRsaSize;
    blob->cbPaddingAlgId = algIdSize;
    blob->cbPaddingLabel = 0;

    // Merge 2 key blobs (AES + RSA)
    memcpy(buffer + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB), bufferEncryptedAesKey, bufferEncryptedAesKeySize);
    memcpy(buffer + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + bufferEncryptedAesKeySize,
        bufferWrappedRsa,
        bufferWrappedRsaSize);
    memcpy(buffer + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + bufferEncryptedAesKeySize + bufferWrappedRsaSize,
        algId,
        algIdSize);
    // No Label

    *out = buffer;
    *outSize = structSize;
}

// Wrap the to-be-imported RSA key in the PKCS#11 format
// Will return a buffer containing BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
// hashAlgId is one of
// NCRYPT_SHA1_ALGORITHM
// NCRYPT_SHA256_ALGORITHM
// NCRYPT_SHA384_ALGORITHM
// NCRYPT_SHA512_ALGORITHM
NTSTATUS ExportKeyWrapped(PBYTE bufferToBeImportedKey,
    DWORD bufferToBeImportedKeySize,
    PBYTE bufferExportKey,
    DWORD bufferExportKeySize,
    LPCWSTR hashAlgId,
    PBYTE* outKeyBlob,
    DWORD* outKeyBlobSize)
{
    NTSTATUS status = STATUS_SUCCESS;

    BCRYPT_KEY_HANDLE aesKey = NULL;
    BCRYPT_KEY_HANDLE rsaExportKey = NULL;

    PBYTE bufferAesKey = NULL;
    DWORD bufferAesKeySize = 0;

    ULONG bytes = 0;
    PBYTE bufferEncryptedAesKey = NULL;
    DWORD bufferEncryptedAesKeySize = 0;

    PBYTE bufferWrappedRsa = NULL;
    DWORD bufferWrappedRsaSize = 0;

    // 1. Create Ephemeral AES key
    status = CreateAesKey(&aesKey, &bufferAesKey, &bufferAesKeySize);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr, "Error during AesKeyWrapPad n == 0. BCryptEncrypt returned: 0x%08X\n", status);
        goto cleanup;
    }

    // 2. Encrypt AES key with RSA Export Key
    status = CreateRsaExportKey(bufferExportKey, bufferExportKeySize, &rsaExportKey);

    status = EncryptAesWithRsaExportKey(bufferAesKey,
        bufferAesKeySize,
        rsaExportKey,
        hashAlgId,
        &bufferEncryptedAesKey,
        &bufferEncryptedAesKeySize);

    // 3. Aes Key Wrap Pad
    // Use AES key to encrypt the RSA Private key
    status = AesKeyWrapPad(aesKey, bufferToBeImportedKey, bufferToBeImportedKeySize, NULL, &bytes);
    bufferWrappedRsa = new BYTE[bytes];
    bufferWrappedRsaSize = bytes;
    status = AesKeyWrapPad(aesKey, bufferToBeImportedKey, bufferToBeImportedKeySize, bufferWrappedRsa, &bytes);
    bufferWrappedRsaSize = bytes;

    // 4. Construct the BCRYPT_PKCS11_RSA_AES_WRAP_BLOB struct
    CreateBCryptStruct(bufferEncryptedAesKey,
        bufferEncryptedAesKeySize,
        bufferWrappedRsa,
        bufferWrappedRsaSize,
        hashAlgId,
        outKeyBlob,
        outKeyBlobSize);

    status = STATUS_SUCCESS;
    printf("Key wrapped successfully. Key Blob Size: %lu bytes.\n", *outKeyBlobSize);

cleanup:
    if (bufferWrappedRsa)
    {
        delete[] bufferWrappedRsa;
    }
    if (bufferEncryptedAesKey)
    {
        delete[] bufferEncryptedAesKey;
    }
    if (bufferAesKey)
    {
        delete[] bufferAesKey;
    }
    if (aesKey)
    {
        BCryptDestroyKey(aesKey);
    }
    if (rsaExportKey)
    {
        BCryptDestroyKey(rsaExportKey);
    }
    return status;
}
