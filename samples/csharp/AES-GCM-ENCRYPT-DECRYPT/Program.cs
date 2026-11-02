// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate an AES-GCM key.
// 2. Use the AES-GCM key to encrypt data.
// 3. Use the AES-GCM key to decrypt data.
//
// Several helper methods are defined below; these contain the specifics of the
// NCrypt API calls. To see the high-level set of steps in this scenario, please
// study the `Main` method.

using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.AesGcm;

internal static class Program
{
    /// <summary>The length of the Additional Authenticated Data used by this sample.</summary>
    private const int AesGcmAadLength = 32;

    private static int Main()
    {
        try
        {
            Console.WriteLine("AziHSM Demonstration: AES-GCM Key Gen --> AES-GCM Encrypt --> AES-GCM Decrypt");
            Console.WriteLine("=============================================================================");

            // Open a handle to the AziHSM via the NCrypt API.
            using NCryptProviderHandle provider = NCryptHelpers.OpenStorageProvider(AziHsmConstants.KspName);
            Console.WriteLine($"Opened NCrypt Storage Provider handle: 0x{provider.DangerousGetHandle().ToInt64():X}");

            // ------------------- Step 1 - Generate the AES-GCM Key ------------------- //
            SampleUtils.PrintHeading("Step 1: Generate AES-GCM Key");

            using NCryptKeyHandle key = CreateAesGcmKey(provider);

            // ------------------ Step 2 - Generate & Encrypt Plaintext ---------------- //
            SampleUtils.PrintHeading("Step 2: Encrypt Plaintext");

            // Plaintext for AES-GCM can be any length; it does not have to match
            // the block size. Pick a random length for this demo.
            byte[] plaintext = SampleUtils.RandomBytes(SampleUtils.RandomInt(64, 256));
            Console.WriteLine($"Plaintext:\n\t{SampleUtils.ToHex(plaintext)}");

            // AES-GCM also needs Additional Authenticated Data.
            byte[] aad = SampleUtils.RandomBytes(AesGcmAadLength);

            // Allocate a buffer for the AES-GCM Initialization Vector.
            //
            // For AES-GCM encryption the AziHSM device generates the IV
            // internally, so we do not generate one ourselves. We still have to
            // pass a buffer so that the AziHSM KSP has somewhere to write the IV
            // that the device produced.
            //
            // The AziHSM KSP requires that this buffer be all zeroes, as the
            // caller's acknowledgement that no IV is being supplied.
            byte[] iv = new byte[AziHsmConstants.AesGcmIvLengthBytes];
            if (Array.Exists(iv, static value => value != 0))
            {
                throw new InvalidOperationException("The IV buffer must be all zeroes before encryption");
            }

            Console.WriteLine($"AAD:\n\t{SampleUtils.ToHex(aad)}");
            Console.WriteLine($"Pre-Encryption IV:\n\t{SampleUtils.ToHex(iv)}");
            Console.WriteLine();

            // Encrypt the plaintext with the AES-GCM key we just created.
            //
            // Encryption does the following:
            //   1. The AziHSM generates a random IV internally and writes it to
            //      our `iv` buffer.
            //   2. The AziHSM generates the authentication tag internally.
            //   3. The ciphertext is produced.
            byte[] ciphertext = CryptoUtils.EncryptAesGcm(key, plaintext, aad, iv, out byte[] tag);
            if (!Array.Exists(iv, static value => value != 0))
            {
                throw new InvalidOperationException("The AziHSM did not write a generated IV to the caller's buffer");
            }

            Console.WriteLine($"Successfully encrypted plaintext: {ciphertext.Length} bytes of ciphertext.");

            Console.WriteLine($"Ciphertext:\n\t{SampleUtils.ToHex(ciphertext)}");
            Console.WriteLine($"Post-Encryption IV:\n\t{SampleUtils.ToHex(iv)}");
            Console.WriteLine($"Post-Encryption Tag:\n\t{SampleUtils.ToHex(tag)}");

            // --------------------- Step 3 - Decrypt the Ciphertext ------------------- //
            SampleUtils.PrintHeading("Step 3: Decrypt Ciphertext");

            byte[] decrypted = CryptoUtils.DecryptAesGcm(key, ciphertext, aad, iv, tag);
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
            Console.Error.WriteLine($"Unhandled exception in AES-GCM sample: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Creates and finalizes a 256-bit AES key in GCM chaining mode.
    /// </summary>
    private static NCryptKeyHandle CreateAesGcmKey(NCryptProviderHandle provider)
    {
        // Start by creating an AES key handle. The AziHSM KSP does not support
        // named keys, so the key name is null.
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptCreatePersistedKey(
                provider,
                out NCryptKeyHandle key,
                NCryptConstants.BCRYPT_AES_ALGORITHM,
                null,
                0,
                0),
            "Failed NCryptCreatePersistedKey");

        try
        {
            Console.WriteLine($"Created AES key handle: 0x{key.DangerousGetHandle().ToInt64():X}");

            // Set the chaining mode of the AES key to GCM.
            NCryptHelpers.SetStringProperty(
                key,
                NCryptConstants.NCRYPT_CHAINING_MODE_PROPERTY,
                NCryptConstants.BCRYPT_CHAIN_MODE_GCM);

            // Set the AES key length to 256 bits (32 bytes). For AES-GCM, AziHSM
            // supports only 256-bit keys.
            NCryptHelpers.SetUInt32Property(
                key, NCryptConstants.NCRYPT_LENGTH_PROPERTY, AziHsmConstants.AesGcmKeyLengthBits);

            // Complete the key creation process.
            NCryptHelpers.FinalizeKey(key);
            Console.WriteLine("Finalized AES-GCM key successfully.");

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}
