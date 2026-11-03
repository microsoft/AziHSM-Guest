// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Fetch quote and collateral from AziHSM.
// 2. Send quote and collateral to an external service (mocked) for attestation
//    verification, and get an attestation token in return.
// 3. Send (1) the attestation token, (2) a link to the private key and (3) the
//    import key to an external service (mocked) for key wrapping and release.
// 4. Import the wrapped key. (This sample supports both RSA and ECDSA keys.)
// 5. Perform a typical workload - hash signing and verification - using the
//    imported key.
//
// Several helper methods are defined below; these contain the specifics of the
// NCrypt API calls. To see the high-level set of steps in this scenario, please
// study the `Main` method.

using System.Runtime.Versioning;
using System.Text;
using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.AttestUnwrapKey;

[SupportedOSPlatform("windows10.0.10240")]
internal static unsafe class Program
{
    /// <summary>
    /// The AziHSM key attestation nonce buffer is a fixed 128 bytes.
    /// </summary>
    private const int UserDataLength = 128;

    private static int Main(string[] args)
    {
        try
        {
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine(
                "AziHSM Demonstration:\nGet Quote/Collateral --> Mock Attestation --> Mock Key Wrap and Release " +
                "--> Import --> Sign/Verify");
            Console.WriteLine(
                "==================================================================================================");

            // Import the RSA or the ECDSA key in this sample? Default to RSA.
            KeyType keyType = args.Length > 0 ? CryptoUtils.ParseKeyType(args[0]) : KeyType.Rsa;
            Console.WriteLine($"\nWorking with {(keyType == KeyType.Rsa ? "RSA" : "ECDSA")} key.");

            // A buffer that is copied into the AziHSM quote. This should be a
            // unique value - such as the hash of something else - so that you
            // know the quote was freshly generated for you.
            byte[] userData = new byte[UserDataLength];
            Encoding.ASCII.GetBytes(
                "Put your custom data here to be included in the quote. For example hash").CopyTo(userData, 0);

            SampleUtils.PrintHeading("Step 1: Get Quote and Collateral");

            (NCryptProviderHandle provider, NCryptKeyHandle importKey) = CryptoUtils.OpenProviderAndUnwrapKey();
            using (provider)
            using (importKey)
            {
                AziHsmClaim claim = GetQuoteAndCertificate(importKey, userData);

                SampleUtils.PrintHeading("Step 2: Mock Attestation");

                // In a real-world scenario you would send the quote and
                // collateral to an external service for attestation
                // verification. Here we just report their sizes and return a
                // mock attestation token.
                int attestationToken = MockAttestation(claim.Quote.Span, claim.Certificate.Span);

                SampleUtils.PrintHeading("Step 3: Mock Key Wrap and Release");

                // (Mocked) link to the private key the user wishes to release
                // and import into AziHSM. In a real-world scenario this would be
                // a link to a private key stored in Azure Key Vault, for example.
                const string linkToPrivateKey = "http://link/to/private/key/you/wish/to/import";

                // In a real-world scenario you would send the attestation token
                // and the key link to an external service for key wrapping and
                // release. Here we wrap a pre-defined key using the import key
                // and return it.
                byte[] keyBlob = MockKeyWrapAndRelease(keyType, attestationToken, linkToPrivateKey, importKey);

                SampleUtils.PrintHeading("Step 4: Import Wrapped Key");

                using NCryptKeyHandle importedKey = CryptoUtils.ImportWrappedKey(
                    provider,
                    importKey,
                    keyBlob,
                    keyType,
                    // The hardcoded RSA key is 2048-bit; the EC key is P-256.
                    keyType == KeyType.Rsa ? 2048 : 256,
                    NCryptConstants.NCRYPT_ALLOW_SIGNING_FLAG);

                SampleUtils.PrintHeading("Step 5: Sign with imported key and Verify");

                if (keyType == KeyType.Rsa)
                {
                    // For RSA signing, pick the hash size to match the hash
                    // algorithm: SHA-256 -> 32, SHA-384 -> 48, SHA-512 -> 64.
                    byte[] signature = CryptoUtils.SignVerifyRsa(
                        importedKey,
                        hashSize: 32,
                        NCryptConstants.BCRYPT_SHA256_ALGORITHM,
                        SampleKeys.RsaMessage);

                    // RSA PKCS#1 signatures are deterministic, so the result can
                    // be compared against a pre-calculated value.
                    if (!signature.AsSpan().SequenceEqual(SampleKeys.ExpectedRsaSignature))
                    {
                        throw new InvalidOperationException(
                            "Signature verification failed. Expected signature does not match the actual signature.");
                    }

                    Console.WriteLine("Signature matches pre-calculated value");
                }
                else
                {
                    // For ECDSA signing, pick the hash size to match the curve:
                    // P-256 -> 32, P-384 -> 48, P-521 -> 66. The key in this
                    // sample is P-256.
                    CryptoUtils.SignVerifyEcdsa(importedKey, hashSize: 32, SampleKeys.EcdsaMessage);
                }
            }

            SampleUtils.PrintHeading("Sample finished successfully");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled exception in ATTEST-UNWRAP-KEY sample: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Fetches the quote and collateral from AziHSM. Both are in an opaque
    /// format.
    /// </summary>
    /// <param name="importKey">A handle to the AziHSM built-in import/unwrapping key.</param>
    /// <param name="userData">
    /// A fixed-size (128 byte) nonce that is copied into the quote, so that the
    /// caller can tell the quote was generated for this request.
    /// </param>
    private static AziHsmClaim GetQuoteAndCertificate(NCryptKeyHandle importKey, byte[] userData)
    {
        if (userData.Length != UserDataLength)
        {
            throw new ArgumentException(
                $"User data must be exactly {UserDataLength} bytes", nameof(userData));
        }

        byte[] claimBuffer;

        fixed (byte* pUserData = userData)
        {
            NCryptBuffer nonce = new()
            {
                cbBuffer = UserDataLength,
                BufferType = NCryptConstants.NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
                pvBuffer = pUserData,
            };

            NCryptBufferDesc parameterList = new()
            {
                ulVersion = NCryptConstants.NCRYPTBUFFER_VERSION,
                cBuffers = 1,
                pBuffers = &nonce,
            };

            // Use `NCryptCreateClaim` to obtain the unwrapping key's attestation
            // report plus its certificate chain. Call once to get the size.
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptCreateClaim(
                    importKey,
                    null,
                    AziHsmConstants.ClaimTypeKeyAttestation,
                    parameterList,
                    Span<byte>.Empty,
                    out uint size,
                    0),
                "Failed 1st NCryptCreateClaim");

            if (size == 0)
            {
                throw new InvalidDataException("Claim size must be non-zero");
            }

            claimBuffer = new byte[size];
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptCreateClaim(
                    importKey,
                    null,
                    AziHsmConstants.ClaimTypeKeyAttestation,
                    parameterList,
                    claimBuffer,
                    out size,
                    0),
                "Failed 2nd NCryptCreateClaim");

            if (size == 0 || size > claimBuffer.Length)
            {
                throw new InvalidDataException($"Unexpected claim size: {size}");
            }

            // The pre-allocated buffer may be larger than the actual claim.
            if (size != claimBuffer.Length)
            {
                claimBuffer = claimBuffer[..(int)size];
            }
        }

        return AziHsmClaim.Parse(claimBuffer);
    }

    /// <summary>
    /// You should not care about the implementation of this method, as it mocks
    /// the behavior of an external service that:
    /// <list type="number">
    ///   <item><description>Verifies the quote and collateral.</description></item>
    ///   <item><description>Returns an attestation token.</description></item>
    /// </list>
    /// </summary>
    private static int MockAttestation(ReadOnlySpan<byte> quote, ReadOnlySpan<byte> collateral)
    {
        if (quote.IsEmpty)
        {
            throw new ArgumentException("Quote buffer must not be empty", nameof(quote));
        }

        if (collateral.IsEmpty)
        {
            throw new ArgumentException("Collateral buffer must not be empty", nameof(collateral));
        }

        Console.WriteLine($"Quote: {quote.Length} bytes. Collateral: {collateral.Length} bytes.");

        // Skip the actual attestation and verification of the quote and
        // collateral, and return a mock attestation token. In reality this is
        // typically a JWT; a number is used here for simplicity.
        return 123;
    }

    /// <summary>
    /// You should not care about the implementation of this method, as it mocks
    /// the behavior of an external service that:
    /// <list type="number">
    ///   <item><description>Verifies the attestation token.</description></item>
    ///   <item><description>Obtains the private key from the link.</description></item>
    ///   <item><description>
    ///     Wraps the private key, given the public part of the AziHSM's
    ///     unwrap/import key.
    ///   </description></item>
    ///   <item><description>Returns the wrapped key blob.</description></item>
    /// </list>
    /// </summary>
    /// <param name="importKey">
    /// Why do we need the import key here? The handle is only needed for
    /// mocking purposes. The external service would typically obtain the import
    /// key from the attestation token.
    /// </param>
    private static byte[] MockKeyWrapAndRelease(
        KeyType keyType,
        int attestationToken,
        string linkToPrivateKey,
        NCryptKeyHandle importKey)
    {
        // Mock verification.
        if (attestationToken == 0)
        {
            throw new ArgumentException($"Invalid attestation token: {attestationToken}", nameof(attestationToken));
        }

        if (string.IsNullOrEmpty(linkToPrivateKey))
        {
            throw new ArgumentException("Invalid link to private key", nameof(linkToPrivateKey));
        }

        // The hash algorithm used during key wrap. SHA-1, SHA-256, SHA-384 and
        // SHA-512 are all supported.
        const string hashAlgorithm = NCryptConstants.NCRYPT_SHA256_ALGORITHM;

        // For this sample, use a pre-generated private key (DER-encoded PKCS#8).
        byte[] keyToImport = keyType == KeyType.Rsa ? SampleKeys.RsaPrivateKey : SampleKeys.EcdsaPrivateKey;

        // Export the public half of the import key so we can wrap for it.
        byte[] importKeyPublicBlob = NCryptHelpers.ExportKey(importKey, NCryptConstants.BCRYPT_RSAPUBLIC_BLOB);

        byte[] keyBlob = RsaWrapUtils.WrapKey(keyToImport, importKeyPublicBlob, hashAlgorithm);
        if (keyBlob.Length == 0)
        {
            throw new InvalidOperationException("Wrapped key blob must not be empty");
        }

        return keyBlob;
    }
}
