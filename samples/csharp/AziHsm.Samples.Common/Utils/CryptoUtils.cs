// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines common crypto operations that use the NCrypt API.

using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.Common;

/// <summary>
/// The kinds of asymmetric key the samples can import into the AziHSM.
/// </summary>
public enum KeyType
{
    Rsa,
    Ecdsa,
}

/// <summary>
/// Crypto operations performed through the AziHSM KSP.
/// </summary>
public static unsafe class CryptoUtils
{
    /// <summary>
    /// Parses a key type from a string, case-insensitively.
    /// </summary>
    public static KeyType ParseKeyType(string value) => value.ToLowerInvariant() switch
    {
        "rsa" => KeyType.Rsa,
        "ecdsa" or "ec" => KeyType.Ecdsa,
        _ => throw new ArgumentException($"Invalid key type: {value}. Supported types: RSA, ECDSA", nameof(value)),
    };

    /// <summary>
    /// Opens the AziHSM provider and the built-in import/unwrapping key.
    /// </summary>
    /// <remarks>
    /// The built-in unwrapping key is the RSA key pair that the device uses to
    /// unwrap imported key blobs. Its public half can be exported so that an
    /// external party can wrap a key for this specific device.
    /// </remarks>
    public static (NCryptProviderHandle Provider, NCryptKeyHandle UnwrapKey) OpenProviderAndUnwrapKey()
    {
        NCryptProviderHandle provider = NCryptHelpers.OpenStorageProvider(AziHsmConstants.KspName);
        try
        {
            NCryptKeyHandle unwrapKey = NCryptHelpers.OpenKey(provider, AziHsmConstants.BuiltInUnwrapKeyName);
            return (provider, unwrapKey);
        }
        catch
        {
            provider.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Imports a wrapped key blob (<c>BCRYPT_PKCS11_RSA_AES_WRAP_BLOB</c>) into
    /// the AziHSM and finalizes it.
    /// </summary>
    /// <param name="provider">An open AziHSM provider handle.</param>
    /// <param name="unwrapKey">The AziHSM built-in unwrapping key.</param>
    /// <param name="keyBlob">The wrapped key blob to import.</param>
    /// <param name="keyType">Whether the wrapped key is an RSA or ECDSA key.</param>
    /// <param name="keySize">
    /// Ignored for RSA (the size is derived from the blob). For ECDSA this must
    /// be 256, 384 or 521.
    /// </param>
    /// <param name="keyUsage">
    /// Ignored for ECDSA (those keys can only sign). For RSA, one of
    /// <c>NCRYPT_ALLOW_DECRYPT_FLAG</c>, <c>NCRYPT_ALLOW_SIGNING_FLAG</c> or
    /// <c>NCRYPT_ALLOW_KEY_IMPORT_FLAG</c>.
    /// </param>
    public static NCryptKeyHandle ImportWrappedKey(
        NCryptProviderHandle provider,
        NCryptKeyHandle unwrapKey,
        ReadOnlySpan<byte> keyBlob,
        KeyType keyType,
        int keySize,
        uint keyUsage)
    {
        // The algorithm identifier must match the type of key being imported.
        string algorithm = keyType == KeyType.Rsa
            ? NCryptConstants.BCRYPT_RSA_ALGORITHM
            : keySize switch
            {
                256 => NCryptConstants.BCRYPT_ECDSA_P256_ALGORITHM,
                384 => NCryptConstants.BCRYPT_ECDSA_P384_ALGORITHM,
                521 => NCryptConstants.BCRYPT_ECDSA_P521_ALGORITHM,
                _ => throw new ArgumentOutOfRangeException(
                    nameof(keySize), keySize, "Invalid key size for an ECDSA key. Expected 256, 384 or 521"),
            };

        byte[] algorithmBytes = NCryptHelpers.NullTerminatedUtf16(algorithm);

        NCryptKeyHandle importedKey;

        fixed (byte* pAlgorithm = algorithmBytes)
        {
            // NCrypt receives the algorithm identifier through a parameter list.
            NCryptBuffer parameter = new()
            {
                BufferType = NCryptConstants.NCRYPTBUFFER_PKCS_ALG_ID,
                cbBuffer = (uint)algorithmBytes.Length,
                pvBuffer = pAlgorithm,
            };

            NCryptBufferDesc parameterList = new()
            {
                ulVersion = NCryptConstants.NCRYPTBUFFER_VERSION,
                cBuffers = 1,
                pBuffers = &parameter,
            };

            // `NCRYPT_DO_NOT_FINALIZE_FLAG` keeps the key open for configuration;
            // we finalize it explicitly once the properties below are set.
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptImportKey(
                    provider,
                    unwrapKey,
                    NCryptConstants.BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
                    parameterList,
                    out importedKey,
                    keyBlob,
                    (NCRYPT_FLAGS)NCryptConstants.NCRYPT_DO_NOT_FINALIZE_FLAG),
                "Failed NCryptImportKey");
        }

        try
        {
            if (keyType == KeyType.Rsa)
            {
                // An RSA key can sign or decrypt, so the intended usage has to be
                // stated explicitly before the key is finalized.
                NCryptHelpers.SetUInt32Property(importedKey, NCryptConstants.NCRYPT_KEY_USAGE_PROPERTY, keyUsage);

                // Optionally enable the Chinese Remainder Theorem optimization.
                // It makes RSA operations faster at the cost of more on-device
                // storage per key.
                NCryptHelpers.SetUInt32Property(
                    importedKey,
                    AziHsmConstants.KeyPropertyRsaCrtEnabledName,
                    AziHsmConstants.KeyPropertyRsaCrtEnabledValueEnabled);
            }

            // ECDSA keys need no usage property: they can only sign.
            NCryptHelpers.FinalizeKey(importedKey);
            return importedKey;
        }
        catch
        {
            importedKey.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Signs a hash with an imported RSA key and verifies the signature with the
    /// same key.
    /// </summary>
    /// <param name="key">The imported RSA key.</param>
    /// <param name="hashSize">
    /// The digest size matching <paramref name="hashAlgorithm"/>: 32 for SHA-256,
    /// 48 for SHA-384, 64 for SHA-512.
    /// </param>
    /// <param name="hashAlgorithm">The hash algorithm identifier, used for PKCS#1 padding.</param>
    /// <param name="message">
    /// The value to sign. For sample purposes this stands in for a real digest;
    /// production code must sign an actual hash.
    /// </param>
    public static byte[] SignVerifyRsa(
        NCryptKeyHandle key,
        int hashSize,
        string hashAlgorithm,
        string message)
    {
        byte[] hash = MessageAsHash(message, hashSize);

        // This sample uses PKCS#1 padding. PSS is also supported, via
        // `NCRYPT_PAD_PSS_FLAG` and a `BCRYPT_PSS_PADDING_INFO` structure.
        const NCRYPT_FLAGS paddingFlag = NCRYPT_FLAGS.NCRYPT_PAD_PKCS1_FLAG;

        byte[] signature;

        fixed (char* pHashAlgorithm = hashAlgorithm)
        {
            BCryptPkcs1PaddingInfo paddingInfo = new() { pszAlgId = pHashAlgorithm };

            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptSignHash(key, &paddingInfo, hash, Span<byte>.Empty, out uint size, paddingFlag),
                "Failed 1st NCryptSignHash");

            signature = new byte[size];
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptSignHash(key, &paddingInfo, hash, signature, out size, paddingFlag),
                "Failed 2nd NCryptSignHash");

            if (size != signature.Length)
            {
                signature = signature[..(int)size];
            }

            Console.WriteLine($"Signature size: {signature.Length} bytes.");

            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptVerifySignature(key, &paddingInfo, hash, signature, paddingFlag),
                "Failed RSA NCryptVerifySignature");
        }

        Console.WriteLine("Signature internally verified successfully.");
        return signature;
    }

    /// <summary>
    /// Signs a hash with an imported ECDSA key and verifies the signature with
    /// the same key.
    /// </summary>
    /// <param name="key">The imported ECDSA key.</param>
    /// <param name="hashSize">
    /// The digest size matching the curve: 32 for P-256, 48 for P-384, 66 for P-521.
    /// </param>
    /// <param name="message">
    /// The value to sign. For sample purposes this stands in for a real digest.
    /// </param>
    /// <returns>The raw <c>(r, s)</c> signature; it is not ASN.1 encoded.</returns>
    public static byte[] SignVerifyEcdsa(NCryptKeyHandle key, int hashSize, string message)
    {
        byte[] hash = MessageAsHash(message, hashSize);
        byte[] signature;

        // ECDSA takes no padding information.
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptSignHash(key, null, hash, Span<byte>.Empty, out uint size, 0),
            "Failed 1st NCryptSignHash");

        signature = new byte[size];
        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptSignHash(key, null, hash, signature, out size, 0),
            "Failed 2nd NCryptSignHash");

        if (size != signature.Length)
        {
            signature = signature[..(int)size];
        }

        Console.WriteLine($"Signature size: {signature.Length} bytes.");

        NCryptStatus.ThrowIfFailed(
            NCryptNative.NCryptVerifySignature(key, null, hash, signature, 0),
            "Failed ECDSA NCryptVerifySignature");

        Console.WriteLine("Signature internally verified successfully.");
        return signature;
    }

    /// <summary>
    /// Encrypts and then decrypts a message with an imported RSA key, verifying
    /// that the round trip reproduces the original plaintext.
    /// </summary>
    public static void EncryptDecryptRsa(NCryptKeyHandle key, string hashAlgorithm, string message)
    {
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(message);
        byte[] ciphertext;
        byte[] decrypted;

        fixed (char* pHashAlgorithm = hashAlgorithm)
        {
            // OAEP padding without a label. To use a label, point `pbLabel` at
            // the label bytes and set `cbLabel` to its length.
            BCryptOaepPaddingInfo paddingInfo = new()
            {
                pszAlgId = pHashAlgorithm,
                pbLabel = null,
                cbLabel = 0,
            };

            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptEncrypt(
                    key,
                    plaintext,
                    &paddingInfo,
                    Span<byte>.Empty,
                    out uint size,
                    NCRYPT_FLAGS.NCRYPT_PAD_OAEP_FLAG),
                "Failed 1st NCryptEncrypt");

            ciphertext = new byte[size];
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptEncrypt(
                    key,
                    plaintext,
                    &paddingInfo,
                    ciphertext,
                    out size,
                    NCRYPT_FLAGS.NCRYPT_PAD_OAEP_FLAG),
                "Failed 2nd NCryptEncrypt");

            if (size != ciphertext.Length)
            {
                ciphertext = ciphertext[..(int)size];
            }

            Console.WriteLine($"Encryption successful. Ciphertext length: {ciphertext.Length}");

            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptDecrypt(
                    key,
                    ciphertext,
                    &paddingInfo,
                    Span<byte>.Empty,
                    out size,
                    NCRYPT_FLAGS.NCRYPT_PAD_OAEP_FLAG),
                "Failed 1st NCryptDecrypt");

            decrypted = new byte[size];
            NCryptStatus.ThrowIfFailed(
                NCryptNative.NCryptDecrypt(
                    key,
                    ciphertext,
                    &paddingInfo,
                    decrypted,
                    out size,
                    NCRYPT_FLAGS.NCRYPT_PAD_OAEP_FLAG),
                "Failed 2nd NCryptDecrypt");

            if (size != decrypted.Length)
            {
                decrypted = decrypted[..(int)size];
            }
        }

        Console.WriteLine($"Decryption successful. Decrypted text length: {decrypted.Length}");

        if (!decrypted.AsSpan().SequenceEqual(plaintext))
        {
            throw new InvalidOperationException("Decrypted data does not match the original plaintext");
        }

        Console.WriteLine("Encrypt-decrypt test passed!");
    }

    /// <summary>
    /// Encrypts a plaintext with an AES-GCM key held by the AziHSM.
    /// </summary>
    /// <param name="key">A finalized AES key whose chaining mode is GCM.</param>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="aad">Additional Authenticated Data.</param>
    /// <param name="iv">
    /// A buffer of <see cref="AziHsmConstants.AesGcmIvLengthBytes"/> bytes, filled with
    /// zeroes. The AziHSM device generates the IV internally and writes it here;
    /// the all-zero contents are the caller's acknowledgement that no IV is
    /// being supplied.
    /// </param>
    /// <param name="tag">Receives the authentication tag generated by the device.</param>
    public static byte[] EncryptAesGcm(
        NCryptKeyHandle key,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad,
        Span<byte> iv,
        out byte[] tag)
    {
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException("Plaintext buffer must not be empty", nameof(plaintext));
        }

        if (iv.Length != AziHsmConstants.AesGcmIvLengthBytes)
        {
            throw new ArgumentException($"IV buffer has invalid length: {iv.Length}", nameof(iv));
        }

        // The AziHSM KSP supports a single fixed tag length, so `dwMinLength`
        // and `dwMaxLength` are equal and `dwIncrement` is 0.
        BCryptKeyLengthsStruct tagLengths =
            NCryptHelpers.GetStructProperty<BCryptKeyLengthsStruct>(key, NCryptConstants.BCRYPT_AUTH_TAG_LENGTH);

        byte[] tagBuffer = new byte[tagLengths.dwMinLength];
        byte[] ciphertext;

        fixed (byte* pAad = aad)
        fixed (byte* pIv = iv)
        fixed (byte* pTag = tagBuffer)
        {
            BCryptAuthenticatedCipherModeInfo authInfo = new()
            {
                cbSize = (uint)sizeof(BCryptAuthenticatedCipherModeInfo),
                dwInfoVersion = NCryptConstants.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            };
            authInfo.pbNonce = pIv;
            authInfo.cbNonce = (uint)iv.Length;
            authInfo.pbAuthData = pAad;
            authInfo.cbAuthData = (uint)aad.Length;
            authInfo.pbTag = pTag;
            authInfo.cbTag = (uint)tagBuffer.Length;

            NCryptCipherPaddingInfo paddingInfo = new()
            {
                cbSize = (uint)sizeof(NCryptCipherPaddingInfo),
                // Signals that `pbOtherInfo` carries the authenticated cipher info.
                dwFlags = NCryptConstants.NCRYPT_CIPHER_OTHER_PADDING_FLAG,
                // The IV travels inside `authInfo`, so it is not repeated here.
                pbIV = null,
                cbIV = 0,
                pbOtherInfo = (byte*)&authInfo,
                cbOtherInfo = (uint)sizeof(BCryptAuthenticatedCipherModeInfo),
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

        tag = tagBuffer;
        return ciphertext;
    }

    /// <summary>
    /// Decrypts a ciphertext with an AES-GCM key held by the AziHSM.
    /// </summary>
    /// <param name="key">A finalized AES key whose chaining mode is GCM.</param>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="aad">
    /// The same Additional Authenticated Data that was supplied during encryption.
    /// </param>
    /// <param name="iv">The IV that the AziHSM device generated during encryption.</param>
    /// <param name="tag">The authentication tag that the device generated during encryption.</param>
    public static byte[] DecryptAesGcm(
        NCryptKeyHandle key,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> tag)
    {
        if (ciphertext.IsEmpty)
        {
            throw new ArgumentException("Ciphertext buffer must not be empty", nameof(ciphertext));
        }

        if (tag.IsEmpty)
        {
            throw new ArgumentException("Tag buffer must not be empty", nameof(tag));
        }

        if (iv.Length != AziHsmConstants.AesGcmIvLengthBytes)
        {
            throw new ArgumentException($"IV buffer has invalid length: {iv.Length}", nameof(iv));
        }

        byte[] plaintext;

        fixed (byte* pAad = aad)
        fixed (byte* pIv = iv)
        fixed (byte* pTag = tag)
        {
            BCryptAuthenticatedCipherModeInfo authInfo = new()
            {
                cbSize = (uint)sizeof(BCryptAuthenticatedCipherModeInfo),
                dwInfoVersion = NCryptConstants.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            };
            authInfo.pbNonce = pIv;
            authInfo.cbNonce = (uint)iv.Length;
            authInfo.pbAuthData = pAad;
            authInfo.cbAuthData = (uint)aad.Length;
            authInfo.pbTag = pTag;
            authInfo.cbTag = (uint)tag.Length;

            NCryptCipherPaddingInfo paddingInfo = new()
            {
                cbSize = (uint)sizeof(NCryptCipherPaddingInfo),
                dwFlags = NCryptConstants.NCRYPT_CIPHER_OTHER_PADDING_FLAG,
                pbIV = null,
                cbIV = 0,
                pbOtherInfo = (byte*)&authInfo,
                cbOtherInfo = (uint)sizeof(BCryptAuthenticatedCipherModeInfo),
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
    /// Places a short message into a zero-padded buffer of the given digest
    /// size.
    /// </summary>
    /// <remarks>
    /// The samples sign this buffer directly so that the output is reproducible.
    /// Production code must pass a real message digest to
    /// <c>NCryptSignHash()</c>.
    /// </remarks>
    private static byte[] MessageAsHash(string message, int hashSize)
    {
        byte[] messageBytes = System.Text.Encoding.ASCII.GetBytes(message);
        if (messageBytes.Length > hashSize)
        {
            throw new ArgumentException(
                $"Message is {messageBytes.Length} bytes, which exceeds the {hashSize}-byte hash size",
                nameof(message));
        }

        byte[] hash = new byte[hashSize];
        messageBytes.CopyTo(hash, 0);
        return hash;
    }
}
