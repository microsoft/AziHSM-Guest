// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines general helper functions that are used by several of the
// AziHSM samples.

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AziHsm.Samples.Common;

/// <summary>
/// Small helpers for formatting buffers and generating random test data.
/// </summary>
public static class SampleUtils
{
    /// <summary>
    /// Helper function that creates a string representing a provided buffer as
    /// a string of hexadecimal values.
    /// </summary>
    public static string ToHex(ReadOnlySpan<byte> buffer) =>
        buffer.IsEmpty ? "<empty>" : Convert.ToHexString(buffer);

    /// <summary>
    /// Helper function that returns a buffer of the requested length, filled
    /// with cryptographically random bytes.
    /// </summary>
    public static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    /// <summary>
    /// Helper function that generates a random integer in the specified range,
    /// including <paramref name="min"/> and excluding <paramref name="max"/>.
    /// </summary>
    public static int RandomInt(int min, int max) => RandomNumberGenerator.GetInt32(min, max);

    /// <summary>
    /// Helper function that generates a random integer in the specified range,
    /// while maintaining the result's alignment as a multiple of the provided
    /// <paramref name="multiple"/> integer.
    /// </summary>
    /// <remarks>
    /// This is used to pick plaintext lengths for algorithms such as AES-XTS,
    /// where AziHSM expects the input to be a whole number of blocks.
    /// </remarks>
    public static int RandomIntMultiple(int min, int max, int multiple)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(max, min + 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(multiple, 1);

        int value = RandomInt(min, max);
        return (((value - min) / multiple) * multiple) + min;
    }

    /// <summary>
    /// Helper function that prints a section heading, underlined to match its
    /// own width.
    /// </summary>
    public static void PrintHeading(string title)
    {
        Console.WriteLine();
        Console.WriteLine(title);
        Console.WriteLine(new string('-', title.Length));
    }
}

/// <summary>
/// The attestation report and certificate contained in an AziHSM claim.
/// </summary>
/// <remarks>
/// The claim buffer returned by <c>NCryptCreateClaim()</c> is laid out as
/// follows (all integers little-endian):
/// <code>
/// Header:
///   4 bytes  UINT32  Version (currently 1)
///   4 bytes  UINT32  Total length, including this header
///   4 bytes  UINT32  Length of the attestation report ("quote"), in bytes
///   4 bytes  UINT32  Length of the certificate, in bytes
/// Payload:
///   N bytes          Attestation report
///   M bytes          Certificate
/// </code>
/// The attestation report is binary data in an opaque format. The certificate
/// is a text blob of multiple X.509 certificates in PEM format, separated by
/// a newline.
/// </remarks>
public readonly record struct AziHsmClaim(ReadOnlyMemory<byte> Quote, ReadOnlyMemory<byte> Certificate)
{
    private const int HeaderSize = 4 * sizeof(uint);
    private const uint SupportedVersion = 1;

    /// <summary>
    /// Splits a claim buffer produced by <c>NCryptCreateClaim()</c> into its
    /// attestation report and certificate parts.
    /// </summary>
    /// <exception cref="InvalidDataException">
    /// Thrown when the buffer is malformed or uses an unsupported version.
    /// </exception>
    public static AziHsmClaim Parse(ReadOnlyMemory<byte> claim)
    {
        ReadOnlySpan<byte> span = claim.Span;

        if (span.Length < HeaderSize)
        {
            throw new InvalidDataException(
                $"Claim buffer is too small to contain a header: {span.Length} bytes");
        }

        uint version = BinaryPrimitives.ReadUInt32LittleEndian(span[..4]);
        if (version != SupportedVersion)
        {
            throw new InvalidDataException($"Unsupported claim buffer version: {version}");
        }

        uint totalLength = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(4, 4));
        uint quoteLength = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(8, 4));
        uint certificateLength = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(12, 4));

        if (HeaderSize + (long)quoteLength + certificateLength != totalLength ||
            totalLength != (uint)span.Length)
        {
            throw new InvalidDataException(
                $"Claim buffer length mismatch. Total: {totalLength}, quote: {quoteLength}, " +
                $"certificate: {certificateLength}, actual: {span.Length}");
        }

        if (quoteLength == 0)
        {
            throw new InvalidDataException("Claim buffer contains an empty attestation report");
        }

        if (certificateLength == 0)
        {
            throw new InvalidDataException("Claim buffer contains an empty certificate");
        }

        return new AziHsmClaim(
            claim.Slice(HeaderSize, (int)quoteLength),
            claim.Slice(HeaderSize + (int)quoteLength, (int)certificateLength));
    }
}
