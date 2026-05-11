// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This sample demonstrates querying the properties that AziHSM exposes to user:
//
// 1. "AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
// 2. "AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
//
// For detailed explanation of each property, please refer to related demo below.
//
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

#include <cstdio>
#include <vector>
#include <exception>

#include <windows.h>
#include <ncrypt.h>

#include <wil/resource.h>
#include <wil/result.h>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"

// Query a property from the provider.
HRESULT query(_In_ const NCRYPT_PROV_HANDLE &provider, _In_ LPCWSTR property, _Out_ std::vector<BYTE> &outBuffer)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, provider == 0, "Invalid provider handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, property == nullptr, "Property name must not be null");

    DWORD bytes = 0;
    // Obtain buffer size first
    RETURN_IF_FAILED_MSG(NCryptGetProperty(provider, property, NULL, 0, &bytes, 0), "Failed 1st NCryptGetProperty");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0, "Property %ls returned an empty buffer", property);

    std::vector<BYTE> buffer(bytes);

    RETURN_IF_FAILED_MSG(NCryptGetProperty(provider,
                                           property,
                                           buffer.data(),
                                           (DWORD)buffer.size(),
                                           &bytes, 0),
                         "Failed 2nd NCryptGetProperty");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0, "Property %ls returned 0 bytes", property);
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes > buffer.size(), "Property %ls returned too many bytes: %u", property, bytes);
    // The actual buffer size may be smaller than the initial size
    // You need to use the actual content size
    buffer.resize(bytes);

    outBuffer = std::move(buffer);

    return S_OK;
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
HRESULT queryMaxStorageSizeProperty(_In_ const NCRYPT_PROV_HANDLE &provider)
{
    std::vector<BYTE> buffer;

    UINT32 maxStorageSize = 0;

    RETURN_IF_FAILED_MSG(query(provider, AZIHSM_PROPERTY_MAX_STORAGE_SIZE_NAME, buffer), "Failed query AZIHSM_PROPERTY_MAX_STORAGE_SIZE_NAME");

    LOG_HR_IF_MSG(E_FAIL, buffer.size() != sizeof(UINT32),
                  "Unexpected buffer size for AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY. Expected: %zu, Actual: %zu\n",
                  sizeof(UINT32), buffer.size());

    // Should expect a unsigned 32-bit integer in buffer
    maxStorageSize = *(UINT32 *)buffer.data();

    printf("Max Storage Size: %u Kilo Bytes\n", maxStorageSize);

    return S_OK;
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
HRESULT queryMaxKeyCountProperty(_In_ const NCRYPT_PROV_HANDLE &provider)
{
    std::vector<BYTE> buffer;

    UINT32 maxKeyCount = 0;

    RETURN_IF_FAILED_MSG(query(provider, AZIHSM_PROPERTY_MAX_KEY_COUNT_NAME, buffer), "Failed query AZIHSM_PROPERTY_MAX_KEY_COUNT_NAME");

    LOG_HR_IF_MSG(E_FAIL, buffer.size() != sizeof(UINT32),
                  "Unexpected buffer size for AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY. Expected: %zu, Actual: %zu\n",
                  sizeof(UINT32), buffer.size());

    // Should expect a unsigned 32-bit integer in buffer
    maxKeyCount = *(UINT32 *)buffer.data();

    printf("Max Key Count: %u\n", maxKeyCount);

    return S_OK;
}

int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    try
    {
        printf("AziHSM Demonstration: Querying properties\n");
        printf("=========================================\n");

        set_wil_log_callback();

        // AziHSM Provider
        wil::unique_ncrypt_prov provider;

        printf("\nOpen AziHSM Provider"
               "\n--------------------\n");

        // To use AziHSM, you need to open "Microsoft Azure Integrated HSM Key Storage Provider"
        RETURN_IF_FAILED_MSG(NCryptOpenStorageProvider(provider.put(), AZIHSM_KSP_NAME, 0), "Failed NCryptOpenStorageProvider");
        printf("Opened NCrypt Storage Provider handle: 0x%08x\n", (int)provider.get());

        printf("\nQuery AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
               "\n---------------------------------------------\n");
        RETURN_IF_FAILED_MSG(queryMaxStorageSizeProperty(provider.get()), "Failed queryMaxStorageSizeProperty");

        printf("\nQuery AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
               "\n------------------------------------------\n");
        RETURN_IF_FAILED_MSG(queryMaxKeyCountProperty(provider.get()), "Failed queryMaxKeyCountProperty");

        return S_OK;
    }
    catch (const std::exception &ex)
    {
        fprintf(stderr, "Unhandled exception in QUERY-PROPERTIES sample: %s\n", ex.what());
        return E_FAIL;
    }
    catch (...)
    {
        fprintf(stderr, "Unhandled unknown exception in QUERY-PROPERTIES sample\n");
        return E_FAIL;
    }
}
