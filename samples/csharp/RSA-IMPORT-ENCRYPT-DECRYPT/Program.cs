// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Import an RSA key into the AziHSM by wrapping it into an encrypted blob.
// 2. Use the imported RSA key to encrypt data.
// 3. Use the imported RSA key to decrypt data.
//
// Several helper methods are defined below; these contain the specifics of the
// NCrypt API calls. To see the high-level set of steps in this scenario, please
// study the `Main` method.

using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.RsaImport;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            Console.WriteLine("AziHSM Demonstration: RSA Key Import --> RSA Encrypt --> RSA Decrypt");
            Console.WriteLine("====================================================================");

            RsaKeyLength keyLength = ParseKeyLength(args);
            Console.WriteLine($"The imported RSA key will have a length of {KeyLengthInBits(keyLength)}.");

            (NCryptProviderHandle provider, NCryptKeyHandle unwrapKey) = CryptoUtils.OpenProviderAndUnwrapKey();
            using (provider)
            using (unwrapKey)
            {
                // ---------------------- Step 1 - Import the RSA Key ---------------------- //
                SampleUtils.PrintHeading("Step 1: Import RSA key");

                // Build the wrapped key blob.
                //
                // The hash algorithm specifies what to use for OAEP when
                // generating the blob. This sample uses SHA-256; SHA-1, SHA-384
                // and SHA-512 are also available.
                byte[] keyBlob = WrapRsaKey(unwrapKey, keyLength, NCryptConstants.NCRYPT_SHA256_ALGORITHM);
                Console.WriteLine($"Created wrapped RSA key blob: {keyBlob.Length} bytes of data.");

                // Import the blob into the AziHSM as an RSA key.
                using NCryptKeyHandle importedKey = CryptoUtils.ImportWrappedKey(
                    provider,
                    unwrapKey,
                    keyBlob,
                    KeyType.Rsa,
                    // The key size is deduced from the blob for RSA keys.
                    keySize: -1,
                    NCryptConstants.NCRYPT_ALLOW_DECRYPT_FLAG);

                Console.WriteLine(
                    $"Successfully imported key into AziHSM. Got handle: 0x{importedKey.DangerousGetHandle().ToInt64():X}");

                // --------------------- Step 2 - Encrypt and Decrypt ---------------------- //
                SampleUtils.PrintHeading("Step 2: Encrypt Decrypt test");

                CryptoUtils.EncryptDecryptRsa(
                    importedKey,
                    NCryptConstants.NCRYPT_SHA384_ALGORITHM,
                    "Some messsage you wish to encrypt");
            }

            Console.WriteLine("Demo completed!");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled exception in RSA sample: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Helper function that wraps the sample's RSA private key with the
    /// AziHSM's built-in unwrapping key, producing a blob that can be imported
    /// into the device.
    /// </summary>
    /// <param name="unwrapKey">A handle to the AziHSM built-in unwrapping key.</param>
    /// <param name="keyLength">Which of the sample's RSA keys to wrap.</param>
    /// <param name="hashAlgorithm">The hash algorithm used for OAEP during wrapping.</param>
    private static byte[] WrapRsaKey(
        NCryptKeyHandle unwrapKey,
        RsaKeyLength keyLength,
        string hashAlgorithm)
    {
        // ----------------------- Built-In Unwrap Key Export ----------------------- //
        // Export the public half of the built-in unwrapping key. Anyone holding
        // this public key can wrap a private key for this specific device.
        byte[] unwrapPublicKey = NCryptHelpers.ExportKey(unwrapKey, NCryptConstants.BCRYPT_RSAPUBLIC_BLOB);
        Console.WriteLine($"Exported built-in unwrap public key: {unwrapPublicKey.Length} bytes.");

        // ------------------------- Wrapped Blob Generation ------------------------ //
        // Use the unwrapping key's public half - together with a freshly
        // generated ephemeral AES key - to build the blob that lets us import an
        // external RSA key into the AziHSM. See `RsaWrapUtils.WrapKey` for the
        // details of this process.
        return RsaWrapUtils.WrapKey(RsaKeys.Get(keyLength), unwrapPublicKey, hashAlgorithm);
    }

    /// <summary>
    /// Helper function that searches the command-line arguments provided by the
    /// user for an RSA key length specification. Defaults to 2048 bits.
    /// </summary>
    private static RsaKeyLength ParseKeyLength(string[] args)
    {
        RsaKeyLength result = RsaKeyLength.Rsa2048;

        foreach (string arg in args)
        {
            result = arg.ToLowerInvariant() switch
            {
                "2048" or "2k" => RsaKeyLength.Rsa2048,
                "3072" or "3k" => RsaKeyLength.Rsa3072,
                "4096" or "4k" => RsaKeyLength.Rsa4096,
                _ => result,
            };
        }

        return result;
    }

    private static int KeyLengthInBits(RsaKeyLength keyLength) => keyLength switch
    {
        RsaKeyLength.Rsa2048 => 2048,
        RsaKeyLength.Rsa3072 => 3072,
        RsaKeyLength.Rsa4096 => 4096,
        _ => throw new ArgumentOutOfRangeException(nameof(keyLength), keyLength, "Unknown RSA key length"),
    };
}
