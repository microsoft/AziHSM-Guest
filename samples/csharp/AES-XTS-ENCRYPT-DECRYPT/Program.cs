// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate an AES-XTS key.
// 2. Use the AES-XTS key to encrypt data.
// 3. Use the AES-XTS key to decrypt data.
//
// Several helper methods are defined below; these contain the specifics of the
// NCrypt API calls. To see the high-level set of steps in this scenario, please
// study the `Main` method.

using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.AesXts;

internal static unsafe class Program
{
    private static int Main()
    {
        try
        {
            Console.WriteLine("AziHSM Demonstration: AES-XTS Key Gen --> AES-XTS Encrypt --> AES-XTS Decrypt");
            Console.WriteLine("=============================================================================");

            // Open a handle to the AziHSM via the NCrypt API.
            using NCryptProviderHandle provider = NCryptHelpers.OpenStorageProvider(AziHsmConstants.KspName);
            Console.WriteLine($"Opened NCrypt Storage Provider handle: 0x{provider.DangerousGetHandle().ToInt64():X}");

            // ------------------- Step 1 - Generate the AES-XTS Key ------------------- //
            SampleUtils.PrintHeading("Step 1: Generate AES-XTS Key");

            using NCryptKeyHandle key = CreateAesXtsKey(provider);

            // ------------------ Step 2 - Generate & Encrypt Plaintext ---------------- //
            SampleUtils.PrintHeading("Step 2: Encrypt Plaintext");

            // AziHSM expects AES-XTS plaintext lengths to be multiples of the
            // block size, so pick a random length that satisfies that.
            int plaintextLength = SampleUtils.RandomIntMultiple(64, 256, AziHsmConstants.AesXtsBlockLengthBytes);
            Console.WriteLine($"Plaintext length chosen: {plaintextLength} bytes.");

            byte[] plaintext = SampleUtils.RandomBytes(plaintextLength);
            Console.WriteLine($"Plaintext:\n\t{SampleUtils.ToHex(plaintext)}");

            // AES-XTS needs a tweak value.
            byte[] tweak = SampleUtils.RandomBytes(AziHsmConstants.AesXtsTweakLengthBytes);
            Console.WriteLine($"Tweak buffer:\n\t{SampleUtils.ToHex(tweak)}");

            // The provider may modify the tweak buffer it is given, so pass a
            // copy to each operation and keep the original for decryption.
            byte[] ciphertext = Encrypt(key, plaintext, tweak.AsSpan().ToArray());
            Console.WriteLine($"Successfully encrypted plaintext: {ciphertext.Length} bytes of ciphertext.");
            Console.WriteLine($"Ciphertext:\n\t{SampleUtils.ToHex(ciphertext)}");

            // --------------------- Step 3 - Decrypt the Ciphertext ------------------- //
            SampleUtils.PrintHeading("Step 3: Decrypt Ciphertext");

            byte[] decrypted = Decrypt(key, ciphertext, tweak.AsSpan().ToArray());
            Console.WriteLine($"Successfully decrypted ciphertext: {decrypted.Length} bytes of plaintext.");
            Console.WriteLine($"Decrypted plaintext:\n\t{SampleUtils.ToHex(decrypted)}");

            if (!decrypted.AsSpan().SequenceEqual(plaintext))
            {
                throw new InvalidOperationException(
                    "The decrypted ciphertext does not match the original plaintext");
            }

            Console.WriteLine("The decrypted ciphertext matches the original plaintext!");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled exception in AES-XTS sample: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Helper function that creates and finalizes a 512-bit AES-XTS key.
    /// </summary>
    private static NCryptKeyHandle CreateAesXtsKey(NCryptProviderHandle provider)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptCreatePersistedKey(
                provider,
                out NCryptKeyHandle key,
                NCryptConstants.BCRYPT_XTS_AES_ALGORITHM,
                null,
                0,
                0),
            "Failed NCryptCreatePersistedKey");

        try
        {
            Console.WriteLine($"Created AES key handle: 0x{key.DangerousGetHandle().ToInt64():X}");

            // Set the AES key length to 512 bits (64 bytes). For AES-XTS, AziHSM
            // supports only 512-bit keys.
            NCryptHelpers.SetUInt32Property(
                key, NCryptConstants.NCRYPT_LENGTH_PROPERTY, AziHsmConstants.AesXtsKeyLengthBits);

            NCryptHelpers.FinalizeKey(key);
            Console.WriteLine("Finalized AES-XTS key successfully.");

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Helper function that encrypts the provided plaintext using the provided
    /// key handle.
    /// </summary>
    private static byte[] Encrypt(NCryptKeyHandle key, ReadOnlySpan<byte> plaintext, Span<byte> tweak)
    {
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException("Plaintext buffer must not be empty", nameof(plaintext));
        }

        if (plaintext.Length % AziHsmConstants.AesXtsBlockLengthBytes != 0)
        {
            throw new ArgumentException(
                $"Plaintext size must be a multiple of {AziHsmConstants.AesXtsBlockLengthBytes} bytes", nameof(plaintext));
        }

        if (tweak.Length != AziHsmConstants.AesXtsTweakLengthBytes)
        {
            throw new ArgumentException(
                $"Tweak buffer has invalid length: {tweak.Length}", nameof(tweak));
        }

        byte[] ciphertext;

        fixed (byte* pTweak = tweak)
        {
            // ---------------------------- Parameter Setup ----------------------------- //
            // `NCRYPT_CIPHER_PADDING_INFO` carries the AES-XTS parameters
            // (primarily the tweak value). It is the padding-info object passed
            // to `NCryptEncrypt`.
            NCryptCipherPaddingInfo paddingInfo = new()
            {
                cbSize = (uint)sizeof(NCryptCipherPaddingInfo),
                dwFlags = 0,
                pbIV = pTweak,
                cbIV = (uint)tweak.Length,
                pbOtherInfo = null,
                cbOtherInfo = 0,
            };

            // --------------------------- Performing Encryption ------------------------ //
            // Call `NCryptEncrypt` once to determine how many bytes are needed
            // to store the ciphertext.
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptEncrypt(
                    key,
                    plaintext,
                    &paddingInfo,
                    Span<byte>.Empty,
                    out uint size,
                    NCryptHelpers.CipherPaddingFlag),
                "Failed 1st NCryptEncrypt");

            // Allocate the buffer and call `NCryptEncrypt` a second time to
            // generate the ciphertext.
            ciphertext = new byte[size];
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptEncrypt(
                    key,
                    plaintext,
                    &paddingInfo,
                    ciphertext,
                    out size,
                    NCryptHelpers.CipherPaddingFlag),
                "Failed 2nd NCryptEncrypt");

            if (size != ciphertext.Length)
            {
                ciphertext = ciphertext[..(int)size];
            }
        }

        return ciphertext;
    }

    /// <summary>
    /// Helper function that decrypts the provided ciphertext using the provided
    /// key handle.
    /// </summary>
    private static byte[] Decrypt(NCryptKeyHandle key, ReadOnlySpan<byte> ciphertext, Span<byte> tweak)
    {
        if (ciphertext.IsEmpty)
        {
            throw new ArgumentException("Ciphertext buffer must not be empty", nameof(ciphertext));
        }

        if (ciphertext.Length % AziHsmConstants.AesXtsBlockLengthBytes != 0)
        {
            throw new ArgumentException(
                $"Ciphertext size must be a multiple of {AziHsmConstants.AesXtsBlockLengthBytes} bytes", nameof(ciphertext));
        }

        if (tweak.Length != AziHsmConstants.AesXtsTweakLengthBytes)
        {
            throw new ArgumentException(
                $"Tweak buffer has invalid length: {tweak.Length}", nameof(tweak));
        }

        byte[] plaintext;

        fixed (byte* pTweak = tweak)
        {
            NCryptCipherPaddingInfo paddingInfo = new()
            {
                cbSize = (uint)sizeof(NCryptCipherPaddingInfo),
                dwFlags = 0,
                pbIV = pTweak,
                cbIV = (uint)tweak.Length,
                pbOtherInfo = null,
                cbOtherInfo = 0,
            };

            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptDecrypt(
                    key,
                    ciphertext,
                    &paddingInfo,
                    Span<byte>.Empty,
                    out uint size,
                    NCryptHelpers.CipherPaddingFlag),
                "Failed 1st NCryptDecrypt");

            plaintext = new byte[size];
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptDecrypt(
                    key,
                    ciphertext,
                    &paddingInfo,
                    plaintext,
                    out size,
                    NCryptHelpers.CipherPaddingFlag),
                "Failed 2nd NCryptDecrypt");

            if (size != plaintext.Length)
            {
                plaintext = plaintext[..(int)size];
            }
        }

        return plaintext;
    }
}
