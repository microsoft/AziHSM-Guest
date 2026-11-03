// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines globals used to interact with the Azure Integrated HSM
// (AziHSM) through the Windows NCrypt API.
//
// These values are not included in the NCrypt interface by default. Thus,
// referencing them is necessary to utilize the full set of features
// implemented by the AziHSM.
//
// For more information, see these links:
//
// * [NCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt)

namespace AziHsm.Samples.Common;

/// <summary>
/// Constants that describe the AziHSM Key Storage Provider and the properties
/// and limits it exposes.
/// </summary>
public static class AziHsmConstants
{
    /// <summary>
    /// The name of the AziHSM Key Storage Provider.
    /// </summary>
    /// <remarks>
    /// Pass this to <c>NCryptOpenStorageProvider()</c> to open a handle to the
    /// AziHSM KSP.
    /// </remarks>
    public const string KspName = "Microsoft Azure Integrated HSM Key Storage Provider";

    // ========================== Provider Properties =========================== //
    // These provider-level properties are read-only and cannot be modified.
    // Pass the name to `NCryptGetProperty()` to read the value.

    /// <summary>
    /// The property holding the maximum number of keys the device can store at
    /// one time.
    /// </summary>
    /// <remarks>
    /// The value is an unsigned 32-bit integer (4 bytes), little-endian.
    /// </remarks>
    public const string PropertyMaxKeyCountName = "AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY";

    /// <summary>
    /// The property holding the maximum storage size, in kilobytes (KB), in
    /// which keys can be stored on the AziHSM device.
    /// </summary>
    /// <remarks>
    /// The value is an unsigned 32-bit integer (4 bytes), little-endian.
    /// </remarks>
    public const string PropertyMaxStorageSizeName = "AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY";

    // ============================= Key Properties ============================= //

    /// <summary>
    /// A custom key property, exclusively for RSA keys, that determines whether
    /// an RSA key is imported as CRT-enabled or CRT-disabled. "CRT" ("Chinese
    /// Remainder Theorem") is an optimization that allows for faster
    /// computation, at the cost of requiring more space to store the key.
    /// </summary>
    /// <remarks>
    /// RSA keys are CRT-enabled by default. To set this explicitly, call
    /// <c>NCryptSetProperty()</c> <i>after</i> <c>NCryptImportKey()</c> and
    /// <i>before</i> <c>NCryptFinalizeKey()</c>.
    /// </remarks>
    public const string KeyPropertyRsaCrtEnabledName = "RsaCrtEnabled";

    /// <summary>The <c>RsaCrtEnabled</c> value meaning "CRT enabled".</summary>
    public const uint KeyPropertyRsaCrtEnabledValueEnabled = 1;

    /// <summary>The <c>RsaCrtEnabled</c> value meaning "CRT disabled".</summary>
    public const uint KeyPropertyRsaCrtEnabledValueDisabled = 0;

    // ======================== Built-In Unwrapping Key ========================= //

    /// <summary>
    /// The name of the AziHSM's built-in unwrapping key.
    /// </summary>
    /// <remarks>
    /// Every AziHSM device has a built-in unwrapping key used internally to
    /// unwrap encrypted blobs containing user-imported keys. Pass this name to
    /// <c>NCryptOpenKey()</c> to obtain a handle, then use
    /// <c>NCryptExportKey()</c> to export the public half so that a key blob can
    /// be encrypted for import.
    /// </remarks>
    public const string BuiltInUnwrapKeyName = "AZIHSM_BUILTIN_UNWRAP_KEY";

    /// <summary>
    /// The blob type used when importing a derived key after a Key Derivation
    /// Function (KDF) operation.
    /// </summary>
    /// <remarks>
    /// With this blob type AziHSM interprets the <c>pbData</c>/<c>cbData</c>
    /// parameters of <c>NCryptImportKey()</c> as a device-internal key handle
    /// rather than as raw derived key material.
    /// </remarks>
    public const string DerivedKeyImportBlobName = "AzIHsmDerivedKeyImportBlob";

    // ================================ AES GCM ================================= //

    /// <summary>The number of bits in an AES-GCM key supported by the AziHSM.</summary>
    public const uint AesGcmKeyLengthBits = 256;

    /// <summary>The number of bytes in an AES-GCM key supported by the AziHSM.</summary>
    public const uint AesGcmKeyLengthBytes = AesGcmKeyLengthBits / 8;

    /// <summary>The number of bytes in an AES-GCM IV used by the AziHSM.</summary>
    public const int AesGcmIvLengthBytes = 12;

    /// <summary>The number of bytes in an AES-GCM authentication tag used by the AziHSM.</summary>
    public const int AesGcmTagLengthBytes = 16;

    // ================================ AES XTS ================================= //

    /// <summary>The number of bits in an AES-XTS key supported by the AziHSM.</summary>
    public const uint AesXtsKeyLengthBits = 512;

    /// <summary>The number of bytes in an AES-XTS tweak value used by the AziHSM.</summary>
    public const int AesXtsTweakLengthBytes = 16;

    /// <summary>The number of bytes in an AES-XTS block used by the AziHSM.</summary>
    public const int AesXtsBlockLengthBytes = 16;

    // ================================= Claims ================================= //

    /// <summary>
    /// The claim type to pass as the <c>dwClaimType</c> parameter of
    /// <c>NCryptCreateClaim()</c>.
    /// </summary>
    public const uint ClaimTypeKeyAttestation = 0x00000000;
}
