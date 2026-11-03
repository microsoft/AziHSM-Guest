// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample. This sample needs
//    additional Azure resources (Microsoft Azure Attestation and an Azure Key
//    Vault with a releasable key).
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Import a key into the AziHSM by performing Secure Key Release with Azure
//    Key Vault and Microsoft Azure Attestation.
// 2. Use the imported key to sign data.
// 3. Verify the signature.
//
// The Secure Key Release specifics live in `SecureKeyReleaseFlow`. To see the
// high-level set of steps in this scenario, please study the `Main` method.

using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.SecureKeyRelease;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: SECURE-KEY-RELEASE.exe <MAA_ENDPOINT> <KEY_URL> [CLIENT_ID]");
                Console.Error.WriteLine("  MAA_ENDPOINT: URL of the Microsoft Azure Attestation endpoint");
                Console.Error.WriteLine("  KEY_URL: URL of the key in Azure Key Vault");
                Console.Error.WriteLine("  CLIENT_ID: Optional Azure Identity Client ID");
                return 1;
            }

            string maaEndpoint = args[0];
            string keyUrl = args[1];
            string? clientId = args.Length > 2 ? args[2] : null;

            // Step 1: Open the AziHSM provider and get the import/unwrapping key handle.
            (NCryptProviderHandle provider, NCryptKeyHandle importKey) = CryptoUtils.OpenProviderAndUnwrapKey();
            using (provider)
            using (importKey)
            {
                Console.WriteLine("Done open_provider_and_key.");

                // A JSON object passed to MAA as the "claims" when attesting the
                // import key. You can include anything you want here and MAA
                // will echo the same payload back in the token after a
                // successful attestation. A real application might include key
                // metadata (key usage, key type, ...) or other custom claims.
                const string payload = """{"key": "value"}""";

                // Step 2: Perform the Secure Key Release.
                (NCryptKeyHandle importedKey, KeyType keyType, int keySize) = SecureKeyReleaseFlow.Run(
                    provider,
                    importKey,
                    payload,
                    maaEndpoint,
                    keyUrl,
                    clientId,
                    NCryptConstants.NCRYPT_ALLOW_SIGNING_FLAG);

                using (importedKey)
                {
                    Console.WriteLine("Done secure_key_release");

                    // Step 3: Simulate a workload with the released key.
                    TestImportedKey(importedKey, keyType, keySize);
                    Console.WriteLine("Done test_imported_key");
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled exception in SECURE-KEY-RELEASE sample: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// A sample workload using the released/imported key. Replace this with your
    /// own workload.
    /// </summary>
    private static void TestImportedKey(NCryptKeyHandle importedKey, KeyType keyType, int keySize)
    {
        // In production you should hash the message. For this sample the message
        // is used directly in place of a digest.
        const string message = "Hello, World!";

        if (keyType == KeyType.Rsa)
        {
            CryptoUtils.SignVerifyRsa(importedKey, 32, NCryptConstants.NCRYPT_SHA256_ALGORITHM, message);
        }
        else
        {
            int hashLength = keySize switch
            {
                256 => 32,
                384 => 48,
                521 => 66,
                _ => throw new ArgumentOutOfRangeException(
                    nameof(keySize), keySize, "Invalid key size for an EC key"),
            };

            CryptoUtils.SignVerifyEcdsa(importedKey, hashLength, message);
        }

        Console.WriteLine("Done test workload.");
    }
}
