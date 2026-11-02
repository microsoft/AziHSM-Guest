// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines helper functions that wrap the most common NCrypt calls
// made by the AziHSM samples.
//
// Most NCrypt functions that return data follow a "call twice" pattern: call
// the function once with a null output buffer to determine how many bytes are
// needed, allocate a buffer of that size, then call it a second time to
// retrieve the data. The number of bytes actually written can be smaller than
// the buffer, so the result is always trimmed to the reported length.
//
// These helpers encapsulate that pattern, so that the samples can focus on the
// AziHSM specifics rather than on buffer bookkeeping.

using System.Text;
using System.Runtime.InteropServices;

namespace AziHsm.Samples.Common.Interop;

/// <summary>
/// Helper functions for calling the NCrypt API.
/// </summary>
public static unsafe class NCryptHelpers
{
    /// <summary>
    /// Requests symmetric cipher padding from <c>NCryptEncrypt</c> or
    /// <c>NCryptDecrypt</c>. This SDK constant is currently absent from the
    /// Windows metadata consumed by CsWin32.
    /// </summary>
    public const NCRYPT_FLAGS CipherPaddingFlag = (NCRYPT_FLAGS)0x00000010;

    /// <summary>
    /// Helper function that opens a handle to the key storage provider with the
    /// given name.
    /// </summary>
    public static NCryptProviderHandle OpenStorageProvider(string providerName)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptOpenStorageProvider(out NCryptProviderHandle provider, providerName, 0),
            $"Failed NCryptOpenStorageProvider for '{providerName}'");

        return provider;
    }

    /// <summary>
    /// Helper function that opens an existing key by name.
    /// </summary>
    public static NCryptKeyHandle OpenKey(NCryptProviderHandle provider, string keyName)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptOpenKey(provider, out NCryptKeyHandle key, keyName, 0, 0),
            $"Failed NCryptOpenKey for '{keyName}'");

        return key;
    }

    /// <summary>
    /// Helper function that reads a named property from a provider or key,
    /// determining the required buffer size automatically.
    /// </summary>
    public static byte[] GetProperty(NCryptHandle target, string property)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptGetProperty(target, property, Span<byte>.Empty, out uint size, 0),
            $"Failed 1st NCryptGetProperty for '{property}'");

        if (size == 0)
        {
            throw new InvalidDataException($"Property '{property}' returned an empty buffer");
        }

        byte[] buffer = new byte[size];
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptGetProperty(target, property, buffer, out size, 0),
            $"Failed 2nd NCryptGetProperty for '{property}'");

        if (size == 0 || size > buffer.Length)
        {
            throw new InvalidDataException($"Property '{property}' returned {size} bytes, expected 1..{buffer.Length}");
        }

        // The value may be shorter than the buffer we allocated; trim to the
        // number of bytes actually written.
        return size == buffer.Length ? buffer : buffer[..(int)size];
    }

    /// <summary>
    /// Helper function that reads a named property whose value is an unsigned
    /// 32-bit integer, represented in little-endian ordering.
    /// </summary>
    public static uint GetUInt32Property(NCryptHandle target, string property)
    {
        byte[] value = GetProperty(target, property);
        if (value.Length != sizeof(uint))
        {
            throw new InvalidDataException(
                $"Property '{property}' returned {value.Length} bytes, expected {sizeof(uint)}");
        }

        return BitConverter.ToUInt32(value);
    }

    /// <summary>
    /// Helper function that reads a named property whose value is a structure.
    /// </summary>
    public static T GetStructProperty<T>(NCryptHandle target, string property)
        where T : unmanaged
    {
        T value = default;
        Span<byte> buffer = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref value, 1));
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptGetProperty(target, property, buffer, out _, 0),
            $"Failed NCryptGetProperty for '{property}'");

        return value;
    }

    /// <summary>
    /// Helper function that sets a named property from a raw byte buffer.
    /// </summary>
    public static void SetProperty(NCryptHandle target, string property, ReadOnlySpan<byte> value)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptSetProperty(target, property, value, 0),
            $"Failed NCryptSetProperty for '{property}'");
    }

    /// <summary>
    /// Helper function that sets a named property whose value is an unsigned
    /// 32-bit integer.
    /// </summary>
    public static void SetUInt32Property(NCryptHandle target, string property, uint value) =>
        SetProperty(target, property, BitConverter.GetBytes(value));

    /// <summary>
    /// Helper function that sets a named property whose value is a wide string.
    /// </summary>
    /// <remarks>
    /// For most string properties, such as the chaining mode, NCrypt expects
    /// the terminating null character to be included in the byte count, so the
    /// string is encoded with one appended.
    ///
    /// A few properties expect the characters only. The ECC curve name is one
    /// of them; see the ECDH-KDF-AES sample for how it is set.
    /// </remarks>
    public static void SetStringProperty(NCryptHandle target, string property, string value) =>
        SetProperty(target, property, NullTerminatedUtf16(value));

    /// <summary>
    /// Helper function that counts a wide string into the byte representation
    /// NCrypt expects, including the null terminator.
    /// </summary>
    public static byte[] NullTerminatedUtf16(string value) => Encoding.Unicode.GetBytes(value + '\0');

    /// <summary>
    /// Helper function that exports a key into the requested blob format,
    /// determining the required buffer size automatically.
    /// </summary>
    public static byte[] ExportKey(NCryptKeyHandle key, string blobType)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptExportKey(key, null, blobType, null, Span<byte>.Empty, out uint size, 0),
            $"Failed 1st NCryptExportKey for '{blobType}'");

        if (size == 0)
        {
            throw new InvalidDataException($"NCryptExportKey reported an empty '{blobType}' blob");
        }

        byte[] buffer = new byte[size];
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptExportKey(key, null, blobType, null, buffer, out size, 0),
            $"Failed 2nd NCryptExportKey for '{blobType}'");

        if (size == 0 || size > buffer.Length)
        {
            throw new InvalidDataException($"NCryptExportKey returned {size} bytes, expected 1..{buffer.Length}");
        }

        return size == buffer.Length ? buffer : buffer[..(int)size];
    }

    /// <summary>
    /// Helper function that completes the key creation or import process,
    /// making the key usable.
    /// </summary>
    public static void FinalizeKey(NCryptKeyHandle key) =>
        NCryptStatus.ThrowIfFailed(NCryptNative.NCryptFinalizeKey(key, 0), "Failed NCryptFinalizeKey");
}
