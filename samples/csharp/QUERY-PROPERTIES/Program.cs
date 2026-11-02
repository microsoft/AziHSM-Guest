// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This sample demonstrates querying the properties that AziHSM exposes to the user:
//
// 1. "AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
// 2. "AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
//
// For a detailed explanation of each property, see the related helper below.
//
// The helper methods contain the specifics of the NCrypt API calls. To see the
// high-level set of steps in this scenario, please study the `Main` method.

using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.QueryProperties;

internal static class Program
{
    private static int Main()
    {
        try
        {
            Console.WriteLine("AziHSM Demonstration: Querying properties");
            Console.WriteLine("=========================================");

            SampleUtils.PrintHeading("Open AziHSM Provider");

            // To use AziHSM, open the
            // "Microsoft Azure Integrated HSM Key Storage Provider".
            using NCryptProviderHandle provider = NCryptHelpers.OpenStorageProvider(AziHsmConstants.KspName);
            Console.WriteLine($"Opened NCrypt Storage Provider handle: 0x{provider.DangerousGetHandle().ToInt64():X}");

            SampleUtils.PrintHeading("Query AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY");
            QueryMaxStorageSize(provider);

            SampleUtils.PrintHeading("Query AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY");
            QueryMaxKeyCount(provider);

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled exception in QUERY-PROPERTIES sample: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Queries "AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY", the maximum storage
    /// size of the AziHSM device.
    /// </summary>
    /// <remarks>
    /// The property value is 4 bytes: the little-endian representation of a
    /// 32-bit unsigned integer holding the maximum storage size in kilobytes (KB).
    ///
    /// Notes:
    ///   1. The value does not reflect the storage remaining in real time.
    ///   2. Built-in keys (such as AZIHSM_BUILTIN_UNWRAP_KEY) consume some of it.
    ///
    /// The combined size of your on-device keys must not exceed this value. For
    /// example, if the value is 16 and each key is 4 KB, the device can hold up
    /// to 4 keys.
    ///
    /// The maximum storage size is determined by the number of "Resource Groups"
    /// the device has, which is in turn determined by the VM size. Each Resource
    /// Group holds up to 4 KB of data and 256 keys.
    /// </remarks>
    private static void QueryMaxStorageSize(NCryptProviderHandle provider)
    {
        uint maxStorageSize = NCryptHelpers.GetUInt32Property(provider, AziHsmConstants.PropertyMaxStorageSizeName);
        Console.WriteLine($"Max Storage Size: {maxStorageSize} Kilo Bytes");
    }

    /// <summary>
    /// Queries "AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY", the maximum number of
    /// keys that can be stored on the AziHSM device at one time.
    /// </summary>
    /// <remarks>
    /// The property value is 4 bytes: the little-endian representation of a
    /// 32-bit unsigned integer.
    ///
    /// Notes:
    ///   1. The value does not reflect the key count remaining in real time.
    ///   2. The actual number of keys may be lower if storage runs out first.
    ///   3. Built-in keys (such as AZIHSM_BUILTIN_UNWRAP_KEY) share the allocation.
    ///
    /// Like the storage size, the maximum key count is determined by the number
    /// of "Resource Groups" the device has, which is determined by the VM size.
    /// Each Resource Group holds up to 4 KB of data and 256 keys.
    /// </remarks>
    private static void QueryMaxKeyCount(NCryptProviderHandle provider)
    {
        uint maxKeyCount = NCryptHelpers.GetUInt32Property(provider, AziHsmConstants.PropertyMaxKeyCountName);
        Console.WriteLine($"Max Key Count: {maxKeyCount}");
    }
}
