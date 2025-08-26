// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This sample demonstrates querying the properties that AziHSM exposes to user:
//
// 1. "AZIHSM_DEVICE_CERT_CHAIN_PROPERTY"
// 2. "AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
// 3. "AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
// 
// For detailed explanation of each property, please refer to related demo below.
//
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

#include <windows.h>
#include <ncrypt.h>

#include "AziHSM/AziHSM.h"

#include <cstdio>

// Force the linking of the NCrypt library into this executable, so we can
// access NCrypt symbols in our code below:
#pragma comment(lib, "ncrypt.lib")

// Query a property from the provider.
static SECURITY_STATUS query(NCRYPT_PROV_HANDLE provider, LPCWSTR property, PBYTE* outBuffer, DWORD* outBufferSize) {
    SECURITY_STATUS status = E_FAIL;

    DWORD bytes = 0;
    PBYTE buffer = NULL;
    DWORD bufferSize = 0;

    // Obtain buffer size first
    status = NCryptGetProperty(provider, property, NULL, 0, &bytes, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get property buffer size. NCryptGetProperty returned: 0x%08x\n", status);
        goto cleanup;
    }

    bufferSize = bytes;
    buffer = new BYTE[bufferSize];
    status = NCryptGetProperty(provider,
        property,
        buffer,
        bufferSize,
        &bytes, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get property. NCryptGetProperty returned: 0x%08x\n", status);
        goto cleanup;
    }
    // The actual buffer size may be smaller than the initial size
    // You need to use the actual content size
    bufferSize = bytes;

    *outBuffer = buffer;
    buffer = NULL;
    *outBufferSize = bufferSize;

    status = S_OK;
cleanup:
    if (buffer)
    {
        delete[] buffer;
    }
    return status;
}

// Query "AZIHSM_DEVICE_CERT_CHAIN_PROPERTY"
// You can retrieve the device certificate chain with this property.
// The returned buffer will contain multiple certificates in PEM format, concatenated together with newline (\n).
// The leaf certificate will be first in the chain.
// Retrieving this property is useful during device attestation, for more information about attestation,
// see another sample: ATTEST-UNWRAP-RSA
static SECURITY_STATUS queryCertChainProperty(NCRYPT_PROV_HANDLE provider) {
    SECURITY_STATUS status = E_FAIL;

    PBYTE buffer = NULL;
    DWORD bufferSize;

    status = query(provider, AZIHSM_PROPERTY_CERT_CHAIN_NAME, &buffer, &bufferSize);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get AZIHSM_PROPERTY_CERT_CHAIN_NAME. query returned: 0x%08x\n", status);
        goto cleanup;
    }

    // To not flood the console with the certificate chain, we will not print it here.
    printf("Retrieved AZIHSM_DEVICE_CERT_CHAIN_PROPERTY successfully. Buffer size: %lu\n", bufferSize);

    status = S_OK;
cleanup:
    if (buffer)
    {
        delete[] buffer;
    }
    return status;
}

// Query "AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
// You can retrieve the maximum storage size of the AziHSM device.
// The returned buffer should have 4 bytes, which is the little-endian representation of a 32-bit unsigned integer
// The integer represents the maximum storage size of the device, in kilo bytes (KB).
// Note:
//   1. It's not reflecting real time storage left.
//   2. Built-in keys (like AZIHSM_BUILTIN_UNWRAP_KEY) will take some storage space.
//
// The combined sizes of your on-device keys should not exceed this value.
// For example, if the value is 16, and if each key is 4KB, then you can store up to 4 keys on the device.
//
// The max storage size of a device is determined by the number of "Resource Group" it has
// "Resource Group" is determined based on VM size.
// Each unit of Resource Group can hold up to 4KB of data and 256 keys.
static SECURITY_STATUS queryMaxStorageSizeProperty(NCRYPT_PROV_HANDLE provider) {
    SECURITY_STATUS status = E_FAIL;

    PBYTE buffer = NULL;
    DWORD bufferSize;

    UINT32 maxStorageSize = 0;

    status = query(provider, AZIHSM_PROPERTY_MAX_STORAGE_SIZE_NAME, &buffer, &bufferSize);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY. query returned: 0x%08x\n", status);
        goto cleanup;
    }

    if (bufferSize != sizeof(UINT32))
    {
        fprintf(stderr, "Unexpected buffer size for AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY. Expected: %zu, Actual: %lu\n",
            sizeof(UINT32), bufferSize);
        status = E_FAIL;
        goto cleanup;
    }

    // Should expect a unsigned 32-bit integer in buffer
    maxStorageSize = *(UINT32*)buffer;

    printf("Max Storage Size: %u Kilo Bytes\n", maxStorageSize);

    status = S_OK;
cleanup:
    if (buffer)
    {
        delete[] buffer;
    }
    return status;
}

// Query "AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
// You can retrieve the maximum number of keys that can be stored on the AziHSM device at the same time.
// The returned buffer should have 4 bytes, which is the little-endian representation of a 32-bit unsigned integer
// The integer represents the maximum number of keys that can be stored.
// Note: 
//   1. It's not reflecting real-time key count left.
//   2. Actual number of keys may be lower if storage runs out first.
//   3. Built-in keys (like AZIHSM_BUILTIN_UNWRAP_KEY) will share the allocation.
//
// The max key allowed of a device is determined by the number of "Resource Group" it has
// "Resource Group" is determined based on VM size.
// Each unit of Resource Group can hold up to 4KB of data and 256 keys.
static SECURITY_STATUS queryMaxKeyCountProperty(NCRYPT_PROV_HANDLE provider) {
    SECURITY_STATUS status = E_FAIL;

    PBYTE buffer = NULL;
    DWORD bufferSize;

    UINT32 maxKeyCount = 0;

    status = query(provider, AZIHSM_PROPERTY_MAX_KEY_COUNT_NAME, &buffer, &bufferSize);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to get AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY. query returned: 0x%08x\n", status);
        goto cleanup;
    }

    if (bufferSize != sizeof(UINT32))
    {
        fprintf(stderr, "Unexpected buffer size for AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY. Expected: %zu, Actual: %lu\n",
            sizeof(UINT32), bufferSize);
        status = E_FAIL;
        goto cleanup;
    }

    // Should expect a unsigned 32-bit integer in buffer
    maxKeyCount = *(UINT32*)buffer;

    printf("Max Key Count: %u\n", maxKeyCount);

    status = S_OK;
cleanup:
    if (buffer)
    {
        delete[] buffer;
    }
    return status;
}

int main() {
    printf("AziHSM Demonstration: Querying properties\n");
    printf("=========================================\n");

    HRESULT status = E_FAIL;

    // AziHSM Provider
    NCRYPT_PROV_HANDLE provider = NULL;

    printf("\nOpen AziHSM Provider"
           "\n--------------------\n");

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
    printf("Opened NCrypt Storage Provider handle: 0x%08x\n", (int) provider);

    printf("\nQuery AZIHSM_DEVICE_CERT_CHAIN_PROPERTY"
           "\n---------------------------------------\n");
    status = queryCertChainProperty(provider);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to query AZIHSM_DEVICE_CERT_CHAIN_PROPERTY: 0x%08x\n",
            status);
        goto cleanup;
    }

    printf("\nQuery AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
           "\n---------------------------------------------\n");
    status = queryMaxStorageSizeProperty(provider);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to query AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY: 0x%08x\n",
            status);
        goto cleanup;
    }

    printf("\nQuery AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
           "\n------------------------------------------\n");
    status = queryMaxKeyCountProperty(provider);
    if (FAILED(status))
    {
        fprintf(stderr,
            "Failed to query AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY: 0x%08x\n",
            status);
        goto cleanup;
    }

    status = S_OK;
cleanup:
    if (provider) {
        NCryptFreeObject(provider);
    }

    return status;
}
