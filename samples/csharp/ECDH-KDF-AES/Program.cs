// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate two ECDH public/private key pairs. (Each key pair represents a
//    separate party: "Alice" (party 1) and "Bob" (party 2).)
// 2. Perform ECDH key exchange, to exchange public keys between the two parties
//    and generate a shared secret.
// 3. Use HKDF to derive the same AES key (from the shared secret) for both
//    parties.
// 4. Perform AES encryption and decryption to verify that the two derived AES
//    keys are identical.
//
// This scenario shows one way to use the AziHSM to establish a secure
// communication channel between two parties. Even though both parties live in
// the same user-space process in this demonstration, the same flow applies to
// two completely separate/isolated parties.
//
// Several helper methods are defined below; these contain the specifics of the
// NCrypt API calls. To see the high-level set of steps in this scenario, please
// study the `Main` method.

using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.EcdhKdfAes;

/// <summary>The AES modes this sample can derive a key for.</summary>
internal enum AesMode
{
    Cbc,
    Gcm,
}

internal static unsafe class Program
{
    private const int AesGcmAadLength = 32;
    private const int AesCbcIvLength = 16;

    private static int Main(string[] args)
    {
        try
        {
            Console.WriteLine("AziHSM Demonstration: ECDH Generate --> ECDH Exchange --> KDF AES --> AES Enc/Dec");
            Console.WriteLine("=================================================================================");

            AesMode aesMode = ParseAesMode(args);
            Console.WriteLine("Keys will be derived using HKDF.");
            Console.WriteLine(
                $"An {(aesMode == AesMode.Gcm ? "AES-GCM" : "AES-CBC")} key will be derived and used for " +
                "encryption & decryption.");

            // Open a handle to the AziHSM via the NCrypt API.
            using NCryptProviderHandle provider = NCryptHelpers.OpenStorageProvider(AziHsmConstants.KspName);
            Console.WriteLine($"Opened NCrypt Storage Provider handle: 0x{provider.DangerousGetHandle().ToInt64():X}");

            // ------------- Step 1 - Generate ECDH Key Pairs (Alice & Bob) ------------ //
            SampleUtils.PrintHeading("Step 1: Generate ECDH Key Pairs for Alice and Bob");

            const string curveName = NCryptConstants.BCRYPT_ECC_CURVE_NISTP256;

            using NCryptKeyHandle aliceKey = CreateEcdhKey(provider, curveName);
            Console.WriteLine($"Generated Alice's ECDH key pair. Key handle: 0x{aliceKey.DangerousGetHandle().ToInt64():X}");

            using NCryptKeyHandle bobKey = CreateEcdhKey(provider, curveName);
            Console.WriteLine($"Generated Bob's ECDH key pair. Key handle: 0x{bobKey.DangerousGetHandle().ToInt64():X}");

            // ----------------- Step 2 - Export & Exchange Public Keys ---------------- //
            SampleUtils.PrintHeading("Step 2: Export and Exchange Public Keys");

            byte[] alicePublicKey = NCryptHelpers.ExportKey(aliceKey, NCryptConstants.BCRYPT_ECCPUBLIC_BLOB);
            Console.WriteLine($"Exported Alice's public key: {alicePublicKey.Length} bytes");

            byte[] bobPublicKey = NCryptHelpers.ExportKey(bobKey, NCryptConstants.BCRYPT_ECCPUBLIC_BLOB);
            Console.WriteLine($"Exported Bob's public key: {bobPublicKey.Length} bytes");

            // Each party imports the other's public key.
            using NCryptKeyHandle aliceImportedBobKey = ImportEcdhPublicKey(provider, bobPublicKey);
            using NCryptKeyHandle bobImportedAliceKey = ImportEcdhPublicKey(provider, alicePublicKey);

            // -------------------- Step 3 - Generate Shared Secrets ------------------- //
            SampleUtils.PrintHeading("Step 3: Generate Shared Secrets");

            using NCryptSecretHandle aliceSecret = GenerateSecret(aliceKey, aliceImportedBobKey);
            Console.WriteLine($"Alice generated shared secret. Handle: 0x{aliceSecret.DangerousGetHandle().ToInt64():X}");

            using NCryptSecretHandle bobSecret = GenerateSecret(bobKey, bobImportedAliceKey);
            Console.WriteLine($"Bob generated shared secret. Handle: 0x{bobSecret.DangerousGetHandle().ToInt64():X}");

            // --------------- Step 4 - Derive AES Keys from Shared Secrets ------------ //
            SampleUtils.PrintHeading("Step 4: Derive AES Keys using HKDF");

            // Demonstrate the generation of 256-bit keys.
            const uint keyBitLength = 256;
            const string hashAlgorithm = NCryptConstants.BCRYPT_SHA256_ALGORITHM;

            using NCryptKeyHandle aliceAesKey = DeriveAesKey(provider, aliceSecret, keyBitLength, hashAlgorithm, aesMode);
            Console.WriteLine($"Alice derived AES key. Handle: 0x{aliceAesKey.DangerousGetHandle().ToInt64():X}");

            using NCryptKeyHandle bobAesKey = DeriveAesKey(provider, bobSecret, keyBitLength, hashAlgorithm, aesMode);
            Console.WriteLine($"Bob derived AES key. Handle: 0x{bobAesKey.DangerousGetHandle().ToInt64():X}");

            // ------------------ Step 5 - Test Encryption & Decryption ---------------- //
            SampleUtils.PrintHeading("Step 5: Test Encryption and Decryption");

            byte[] plaintext = SampleUtils.RandomBytes(64);
            Console.WriteLine($"Original plaintext:\n\t{SampleUtils.ToHex(plaintext)}");

            byte[] decrypted = aesMode == AesMode.Gcm
                ? RoundTripAesGcm(aliceAesKey, bobAesKey, plaintext)
                : RoundTripAesCbc(aliceAesKey, bobAesKey, plaintext);

            if (!decrypted.AsSpan().SequenceEqual(plaintext))
            {
                throw new InvalidOperationException("Decrypted data does not match the original plaintext");
            }

            Console.WriteLine(
                $"{(aesMode == AesMode.Gcm ? "AES-GCM" : "AES-CBC")} encryption/decryption test PASSED!");

            Console.WriteLine();
            Console.WriteLine("ECDH Key Exchange + HKDF + AES Encryption Demo completed successfully!");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled exception in ECDH-KDF-AES sample: {ex.Message}");
            return 1;
        }
    }

    // ============================== NCrypt Helpers ============================== //

    /// <summary>
    /// Helper function that invokes AziHSM (via NCrypt) to generate an ECC key
    /// pair on the given curve.
    /// </summary>
    private static NCryptKeyHandle CreateEcdhKey(NCryptProviderHandle provider, string eccCurveName)
    {
        // Create an ECDH key with no flags and no key name.
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptCreatePersistedKey(
                provider,
                out NCryptKeyHandle key,
                NCryptConstants.BCRYPT_ECDH_ALGORITHM,
                null,
                0,
                0),
            "Failed NCryptCreatePersistedKey for ECDH");

        try
        {
            // Set the key's ECC curve name property to use the provided curve.
            //
            // This property is one of the few that expects the characters of the
            // string only, without a terminating null character.
            NCryptHelpers.SetProperty(
                key,
                NCryptConstants.NCRYPT_ECC_CURVE_NAME_PROPERTY,
                System.Text.Encoding.Unicode.GetBytes(eccCurveName));

            // Finish the key creation process.
            NCryptHelpers.FinalizeKey(key);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Helper function that invokes AziHSM (via NCrypt) to import a public ECDH
    /// key.
    /// </summary>
    private static NCryptKeyHandle ImportEcdhPublicKey(NCryptProviderHandle provider, ReadOnlySpan<byte> publicKeyBlob)
    {
        if (publicKeyBlob.IsEmpty)
        {
            throw new ArgumentException("ECDH public key buffer must not be empty", nameof(publicKeyBlob));
        }

        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptImportKey(
                provider,
                // No unwrapping key: this is a plaintext public key blob.
                null,
                NCryptConstants.BCRYPT_ECCPUBLIC_BLOB,
                null,
                out NCryptKeyHandle key,
                publicKeyBlob,
                0),
            "Failed NCryptImportKey for ECDH");

        return key;
    }

    /// <summary>
    /// Helper function that invokes AziHSM (via NCrypt) to generate a secret
    /// from ECDH keys.
    /// </summary>
    private static NCryptSecretHandle GenerateSecret(NCryptKeyHandle privateKey, NCryptKeyHandle publicKey)
    {
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptSecretAgreement(privateKey, publicKey, out NCRYPT_SECRET_HANDLE secret, 0),
            "Failed NCryptSecretAgreement");

        // CsWin32 projects this output as a raw handle, so wrap it in the
        // generated NCrypt SafeHandle to release it with NCryptFreeObject.
        return new NCryptSecretHandle(unchecked((IntPtr)(long)(ulong)secret.Value));
    }

    /// <summary>
    /// Helper function that derives an AES key from the provided secret handle.
    /// </summary>
    /// <remarks>
    /// The HKDF info and salt both influence the resulting key. Alice and Bob
    /// must derive the <i>same</i> AES key, so constant values are used here.
    /// </remarks>
    private static NCryptKeyHandle DeriveAesKey(
        NCryptProviderHandle provider,
        NCryptSecretHandle secret,
        uint keyBitLength,
        string hashAlgorithm,
        AesMode aesMode)
    {
        const string hkdfInfo = "info";
        const string hkdfSalt = "salt";

        return DeriveAesKeyHkdf(provider, secret, keyBitLength, hashAlgorithm, hkdfInfo, hkdfSalt, aesMode);
    }

    /// <summary>
    /// Helper function that invokes AziHSM (via NCrypt) to derive an AES key
    /// using HKDF, then imports the result back into the device so that it can
    /// be used.
    /// </summary>
    private static NCryptKeyHandle DeriveAesKeyHkdf(
        NCryptProviderHandle provider,
        NCryptSecretHandle secret,
        uint keyBitLength,
        string hashAlgorithm,
        string info,
        string salt,
        AesMode aesMode)
    {
        // Select the chaining mode for the derived AES key.
        string chainingMode = aesMode == AesMode.Gcm
            ? NCryptConstants.BCRYPT_CHAIN_MODE_GCM
            : NCryptConstants.BCRYPT_CHAIN_MODE_CBC;

        if (aesMode == AesMode.Gcm)
        {
            // AziHSM supports only 256-bit keys for AES-GCM.
            keyBitLength = 256;
        }
        else if (keyBitLength == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(keyBitLength), keyBitLength, "AES-CBC key bit length must be non-zero");
        }

        // The hash algorithm is passed as a wide string including its
        // terminating null character. The HKDF info and salt are passed as the
        // string characters only.
        byte[] hashAlgorithmBytes = NCryptHelpers.NullTerminatedUtf16(hashAlgorithm);
        byte[] infoBytes = System.Text.Encoding.Unicode.GetBytes(info);
        byte[] saltBytes = System.Text.Encoding.Unicode.GetBytes(salt);

        byte[] derivedKeyBlob;
        bool secretAddedRef = false;

        try
        {
            secret.DangerousAddRef(ref secretAddedRef);
            NCRYPT_SECRET_HANDLE secretHandle = (NCRYPT_SECRET_HANDLE)secret.DangerousGetHandle();

            fixed (byte* pHashAlgorithm = hashAlgorithmBytes)
            fixed (byte* pInfo = infoBytes)
            fixed (byte* pSalt = saltBytes)
            {
                NCryptBuffer* parameters = stackalloc NCryptBuffer[4];

                // HASH ALGORITHM: which hashing algorithm to use for key derivation.
                parameters[0] = new NCryptBuffer
                {
                    BufferType = NCryptConstants.KDF_HASH_ALGORITHM,
                    cbBuffer = (uint)hashAlgorithmBytes.Length,
                    pvBuffer = pHashAlgorithm,
                };

                // INFO: a custom string factored into the key derivation process.
                parameters[1] = new NCryptBuffer
                {
                    BufferType = NCryptConstants.KDF_HKDF_INFO,
                    cbBuffer = (uint)infoBytes.Length,
                    pvBuffer = pInfo,
                };

                // SALT: plays a similar role to the HKDF info.
                parameters[2] = new NCryptBuffer
                {
                    BufferType = NCryptConstants.KDF_HKDF_SALT,
                    cbBuffer = (uint)saltBytes.Length,
                    pvBuffer = pSalt,
                };

                // KEY BIT LENGTH: how many bits the derived AES key should have.
                parameters[3] = new NCryptBuffer
                {
                    BufferType = NCryptConstants.KDF_KEYBITLENGTH,
                    cbBuffer = sizeof(uint),
                    pvBuffer = &keyBitLength,
                };

                NCryptBufferDesc parameterList = new()
                {
                    ulVersion = NCryptConstants.NCRYPTBUFFER_VERSION,
                    cBuffers = 4,
                    pBuffers = parameters,
                };

                NCryptStatus.ThrowIfFailed(
                    NCryptNative.NCryptDeriveKey(
                        secretHandle,
                        NCryptConstants.BCRYPT_HKDF_ALGORITHM,
                        parameterList,
                        Span<byte>.Empty,
                        out uint size,
                        0),
                    "Failed 1st NCryptDeriveKey");

                if (size == 0)
                {
                    throw new InvalidDataException("Derived key buffer length must be non-zero");
                }

                // AziHSM's return data from `NCryptDeriveKey` differs from other
                // NCrypt providers. Instead of the derived key's raw bytes, AziHSM
                // returns an opaque, device-internal key handle.
                //
                // This keeps the derived key inside the trusted hardware boundary of
                // the physical AziHSM device. The returned blob is re-imported via
                // `NCryptImportKey` below in order to use it for encryption.
                derivedKeyBlob = new byte[size];
                NCryptStatus.ThrowIfFailed(
                    NCryptNative.NCryptDeriveKey(
                        secretHandle,
                        NCryptConstants.BCRYPT_HKDF_ALGORITHM,
                        parameterList,
                        derivedKeyBlob,
                        out size,
                        0),
                    "Failed 2nd NCryptDeriveKey");

                if (size == 0 || size > derivedKeyBlob.Length)
                {
                    throw new InvalidDataException($"Invalid derived key buffer length returned: {size}");
                }

                if (size != derivedKeyBlob.Length)
                {
                    derivedKeyBlob = derivedKeyBlob[..(int)size];
                }
            }
        }
        finally
        {
            if (secretAddedRef)
            {
                secret.DangerousRelease();
            }
        }

        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptImportKey(
                provider,
                null,
                AziHsmConstants.DerivedKeyImportBlobName,
                null,
                out NCryptKeyHandle derivedKey,
                derivedKeyBlob,
                (NCRYPT_FLAGS)NCryptConstants.NCRYPT_DO_NOT_FINALIZE_FLAG),
            "Failed NCryptImportKey for derived key");

        try
        {
            NCryptHelpers.SetStringProperty(
                derivedKey, NCryptConstants.NCRYPT_CHAINING_MODE_PROPERTY, chainingMode);
            Console.WriteLine($"Set AES key chaining mode to: {chainingMode}.");

            NCryptHelpers.FinalizeKey(derivedKey);
            Console.WriteLine("Finalized AES key successfully.");

            return derivedKey;
        }
        catch
        {
            derivedKey.Dispose();
            throw;
        }
    }

    // ============================ Encryption Helpers ============================ //

    /// <summary>
    /// Helper function that encrypts with Alice's derived key and decrypts with
    /// Bob's, using AES-GCM.
    /// </summary>
    private static byte[] RoundTripAesGcm(
        NCryptKeyHandle aliceKey,
        NCryptKeyHandle bobKey,
        ReadOnlySpan<byte> plaintext)
    {
        // For AES-GCM encryption the AziHSM device generates a random IV and
        // returns it to the caller. The caller must supply an all-zero buffer;
        // AziHSM verifies that and then fills in the generated IV.
        byte[] iv = new byte[AziHsmConstants.AesGcmIvLengthBytes];
        byte[] aad = SampleUtils.RandomBytes(AesGcmAadLength);

        byte[] ciphertext = CryptoUtils.EncryptAesGcm(aliceKey, plaintext, aad, iv, out byte[] tag);
        Console.WriteLine($"Ciphertext:\n\t{SampleUtils.ToHex(ciphertext)}");
        Console.WriteLine($"Generated IV:\n\t{SampleUtils.ToHex(iv)}");

        byte[] decrypted = CryptoUtils.DecryptAesGcm(bobKey, ciphertext, aad, iv, tag);
        Console.WriteLine($"Decrypted plaintext:\n\t{SampleUtils.ToHex(decrypted)}");

        return decrypted;
    }

    /// <summary>
    /// Helper function that encrypts with Alice's derived key and decrypts with
    /// Bob's, using AES-CBC.
    /// </summary>
    private static byte[] RoundTripAesCbc(
        NCryptKeyHandle aliceKey,
        NCryptKeyHandle bobKey,
        ReadOnlySpan<byte> plaintext)
    {
        byte[] iv = SampleUtils.RandomBytes(AesCbcIvLength);

        // The provider modifies the IV buffer it is given, so each operation
        // gets its own copy of the original IV.
        byte[] ciphertext = EncryptAesCbc(aliceKey, plaintext, iv.AsSpan().ToArray());
        Console.WriteLine($"Ciphertext:\n\t{SampleUtils.ToHex(ciphertext)}");

        byte[] decrypted = DecryptAesCbc(bobKey, ciphertext, iv.AsSpan().ToArray());
        Console.WriteLine($"Decrypted plaintext:\n\t{SampleUtils.ToHex(decrypted)}");

        return decrypted;
    }

    /// <summary>
    /// Helper function that encrypts plaintext using AES-CBC. The <paramref name="iv"/> buffer is
    /// modified by the provider.
    /// </summary>
    private static byte[] EncryptAesCbc(NCryptKeyHandle key, ReadOnlySpan<byte> plaintext, Span<byte> iv)
    {
        if (iv.Length != AesCbcIvLength)
        {
            throw new ArgumentException($"AES-CBC IV must be {AesCbcIvLength} bytes, got {iv.Length}", nameof(iv));
        }

        byte[] ciphertext;

        fixed (byte* pIv = iv)
        {
            NCryptCipherPaddingInfo paddingInfo = new()
            {
                cbSize = (uint)sizeof(NCryptCipherPaddingInfo),
                dwFlags = 0,
                pbIV = pIv,
                cbIV = (uint)iv.Length,
                pbOtherInfo = null,
                cbOtherInfo = 0,
            };

            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptEncrypt(
                    key,
                    plaintext,
                    &paddingInfo,
                    Span<byte>.Empty,
                    out uint size,
                    NCryptHelpers.CipherPaddingFlag),
                "Failed 1st NCryptEncrypt");

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
    /// Helper function that decrypts ciphertext using AES-CBC. The <paramref name="iv"/> buffer is
    /// modified by the provider.
    /// </summary>
    private static byte[] DecryptAesCbc(NCryptKeyHandle key, ReadOnlySpan<byte> ciphertext, Span<byte> iv)
    {
        if (iv.Length != AesCbcIvLength)
        {
            throw new ArgumentException($"AES-CBC IV must be {AesCbcIvLength} bytes, got {iv.Length}", nameof(iv));
        }

        byte[] plaintext;

        fixed (byte* pIv = iv)
        {
            NCryptCipherPaddingInfo paddingInfo = new()
            {
                cbSize = (uint)sizeof(NCryptCipherPaddingInfo),
                dwFlags = 0,
                pbIV = pIv,
                cbIV = (uint)iv.Length,
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

    /// <summary>
    /// Examines the command-line arguments to determine which AES mode to use.
    /// Defaults to AES-GCM.
    /// </summary>
    private static AesMode ParseAesMode(string[] args) =>
        args.Length >= 1 && args[0].Equals("cbc", StringComparison.OrdinalIgnoreCase)
            ? AesMode.Cbc
            : AesMode.Gcm;
}
