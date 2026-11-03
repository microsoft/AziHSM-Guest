// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines helper functions related to exporting an RSA key in the
// PKCS#11 format.
// As a user of AziHSM, you should not care about the detail of these functions.
//
// In a real deployment the wrapping is performed by whichever service holds the
// key, such as Azure Key Vault. The samples reproduce it locally so that they
// can run end to end without any external infrastructure.
//
// The wrapping scheme is the PKCS#11 `CKM_RSA_AES_KEY_WRAP` mechanism:
//
//   1. Generate an ephemeral AES-256 key.
//   2. Encrypt that AES key with the recipient's RSA public key (RSA-OAEP).
//   3. Wrap the private key with the AES key using AES Key Wrap with Padding
//      (RFC 5649).
//   4. Concatenate both results behind a PKCS#11 wrapped key blob header.

using System.Buffers.Binary;
using System.Security.Cryptography;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.Common;

/// <summary>
/// Builds the PKCS#11 wrapped key blobs that the AziHSM accepts when importing
/// a key.
/// </summary>
public static class RsaWrapUtils
{
    /// <summary>256 is the only supported AES bit size for Key Wrap.</summary>
    private const int AesKeySizeBits = 256;

    /// <summary>The Alternative Initial Value from RFC 5649, section 3.</summary>
    private const uint AesKeyWrapPadAiv = 0xA65959A6;

    /// <summary>RFC 3394 operates on 8-byte semiblocks.</summary>
    private const int SemiblockSize = 8;

    /// <summary><c>BCRYPT_RSAPUBLIC_MAGIC</c> ('RSA1').</summary>
    private const uint BCryptRsaPublicMagic = 0x31415352;

    /// <summary>
    /// Wraps a private key so that it can be imported into the AziHSM.
    /// </summary>
    /// <param name="keyToWrap">The private key to import, in DER-encoded PKCS#8 form.</param>
    /// <param name="rsaPublicKeyBlob">
    /// The public half of the AziHSM built-in unwrapping key, as exported by
    /// <c>NCryptExportKey()</c> with <c>BCRYPT_RSAPUBLIC_BLOB</c>.
    /// </param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm used for RSA-OAEP. One of <c>SHA1</c>, <c>SHA256</c>,
    /// <c>SHA384</c> or <c>SHA512</c>.
    /// </param>
    /// <returns>A <c>BCRYPT_PKCS11_RSA_AES_WRAP_BLOB</c> ready for <c>NCryptImportKey()</c>.</returns>
    public static byte[] WrapKey(
        ReadOnlySpan<byte> keyToWrap,
        ReadOnlySpan<byte> rsaPublicKeyBlob,
        string hashAlgorithm)
    {
        // 1. Create the ephemeral AES key.
        byte[] aesKey = RandomNumberGenerator.GetBytes(AesKeySizeBits / 8);

        // 2. Encrypt the AES key with the recipient's RSA public key.
        byte[] encryptedAesKey = EncryptAesKeyWithRsa(aesKey, rsaPublicKeyBlob, hashAlgorithm);

        // 3. Wrap the private key with the AES key (RFC 5649).
        byte[] wrappedKey = AesKeyWrapPad(aesKey, keyToWrap);

        // 4. Assemble the blob.
        byte[] blob = BuildPkcs11WrapBlob(encryptedAesKey, wrappedKey, hashAlgorithm);

        Console.WriteLine($"Key wrapped successfully. Key blob size: {blob.Length} bytes.");
        return blob;
    }

    /// <summary>
    /// Assembles a <c>BCRYPT_PKCS11_RSA_AES_WRAP_BLOB</c> from its parts.
    /// </summary>
    /// <param name="wrappedKeyBlob">
    /// The PKCS#11 payload: the RSA-encrypted AES key followed by the
    /// AES-wrapped private key.
    /// </param>
    /// <param name="paddingAlgorithm">The OAEP hash algorithm used to encrypt the AES key.</param>
    public static byte[] BuildPkcs11WrapBlob(ReadOnlySpan<byte> wrappedKeyBlob, string paddingAlgorithm)
    {
        byte[] paddingAlgorithmBytes = NCryptHelpers.NullTerminatedUtf16(paddingAlgorithm);

        int headerSize = 4 * sizeof(uint);
        byte[] blob = new byte[headerSize + wrappedKeyBlob.Length + paddingAlgorithmBytes.Length];
        Span<byte> destination = blob;

        BinaryPrimitives.WriteUInt32LittleEndian(
            destination[..4], NCryptConstants.BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination.Slice(4, 4), (uint)wrappedKeyBlob.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination.Slice(8, 4), (uint)paddingAlgorithmBytes.Length);
        // No padding label.
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12, 4), 0);

        wrappedKeyBlob.CopyTo(destination[headerSize..]);
        paddingAlgorithmBytes.CopyTo(destination[(headerSize + wrappedKeyBlob.Length)..]);

        return blob;
    }

    private static byte[] BuildPkcs11WrapBlob(
        ReadOnlySpan<byte> encryptedAesKey,
        ReadOnlySpan<byte> wrappedKey,
        string paddingAlgorithm)
    {
        byte[] payload = new byte[encryptedAesKey.Length + wrappedKey.Length];
        encryptedAesKey.CopyTo(payload);
        wrappedKey.CopyTo(payload.AsSpan(encryptedAesKey.Length));

        return BuildPkcs11WrapBlob(payload, paddingAlgorithm);
    }

    /// <summary>
    /// Encrypts the ephemeral AES key with an RSA public key using OAEP.
    /// </summary>
    private static byte[] EncryptAesKeyWithRsa(
        ReadOnlySpan<byte> aesKey,
        ReadOnlySpan<byte> rsaPublicKeyBlob,
        string hashAlgorithm)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportParameters(ParseBCryptRsaPublicBlob(rsaPublicKeyBlob));

        RSAEncryptionPadding padding = hashAlgorithm.ToUpperInvariant() switch
        {
            NCryptConstants.BCRYPT_SHA1_ALGORITHM => RSAEncryptionPadding.OaepSHA1,
            NCryptConstants.BCRYPT_SHA256_ALGORITHM => RSAEncryptionPadding.OaepSHA256,
            NCryptConstants.BCRYPT_SHA384_ALGORITHM => RSAEncryptionPadding.OaepSHA384,
            NCryptConstants.BCRYPT_SHA512_ALGORITHM => RSAEncryptionPadding.OaepSHA512,
            _ => throw new ArgumentException($"Unsupported OAEP hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm)),
        };

        return rsa.Encrypt(aesKey, padding);
    }

    /// <summary>
    /// Parses a <c>BCRYPT_RSAPUBLIC_BLOB</c> into <see cref="RSAParameters"/>.
    /// </summary>
    /// <remarks>
    /// The blob is a <c>BCRYPT_RSAKEY_BLOB</c> header
    /// (<c>Magic</c>, <c>BitLength</c>, <c>cbPublicExp</c>, <c>cbModulus</c>,
    /// <c>cbPrime1</c>, <c>cbPrime2</c>) followed by the big-endian public
    /// exponent and modulus.
    /// </remarks>
    private static RSAParameters ParseBCryptRsaPublicBlob(ReadOnlySpan<byte> blob)
    {
        const int headerSize = 6 * sizeof(uint);
        if (blob.Length < headerSize)
        {
            throw new ArgumentException("RSA public key blob is too small", nameof(blob));
        }

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(blob[..4]);
        if (magic != BCryptRsaPublicMagic)
        {
            throw new ArgumentException($"Unexpected RSA public key blob magic: 0x{magic:X8}", nameof(blob));
        }

        int publicExponentLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.Slice(8, 4));
        int modulusLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.Slice(12, 4));

        if (blob.Length < headerSize + publicExponentLength + modulusLength)
        {
            throw new ArgumentException("RSA public key blob is truncated", nameof(blob));
        }

        return new RSAParameters
        {
            Exponent = blob.Slice(headerSize, publicExponentLength).ToArray(),
            Modulus = blob.Slice(headerSize + publicExponentLength, modulusLength).ToArray(),
        };
    }

    /// <summary>
    /// Implements the extended key wrapping process from RFC 5649, section 4.1
    /// (AES Key Wrap with Padding, equivalent to OpenSSL's
    /// <c>EVP_aes_256_wrap_pad</c>).
    /// </summary>
    /// <remarks>
    /// THIS IMPLEMENTATION IS FOR SAMPLE USAGE ONLY. In production the wrapping
    /// is performed by the service that holds the key.
    /// </remarks>
    /// <param name="aesKey">
    /// The Key Encryption Key. AziHSM key wrapping always uses a 256-bit key;
    /// see <see cref="AesKeySizeBits"/>.
    /// </param>
    /// <param name="plaintext">The key material to wrap.</param>
    public static byte[] AesKeyWrapPad(byte[] aesKey, ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException("Nothing to wrap", nameof(plaintext));
        }

        using Aes aes = Aes.Create();
        aes.Key = aesKey;

        // The Alternative Initial Value: the RFC 5649 constant followed by the
        // big-endian Message Length Indicator.
        byte[] icv = new byte[SemiblockSize];
        BinaryPrimitives.WriteUInt32BigEndian(icv.AsSpan(0, 4), AesKeyWrapPadAiv);
        BinaryPrimitives.WriteUInt32BigEndian(icv.AsSpan(4, 4), (uint)plaintext.Length);

        // Zero-pad the plaintext up to a whole number of semiblocks.
        int paddedLength = ((plaintext.Length + SemiblockSize - 1) / SemiblockSize) * SemiblockSize;
        byte[] r = new byte[paddedLength];
        plaintext.CopyTo(r);

        int n = paddedLength / SemiblockSize;
        byte[] output = new byte[paddedLength + SemiblockSize];

        if (n == 1)
        {
            // RFC 5649: a single semiblock is wrapped with one AES-ECB operation
            // over `ICV || P`.
            byte[] block = new byte[2 * SemiblockSize];
            icv.CopyTo(block, 0);
            r.CopyTo(block, SemiblockSize);
            aes.EncryptEcb(block, output, PaddingMode.None);
            return output;
        }

        // RFC 3394 key wrap, using the RFC 5649 ICV as the initial A value.
        Span<byte> a = stackalloc byte[SemiblockSize];
        icv.CopyTo(a);

        Span<byte> block2 = stackalloc byte[2 * SemiblockSize];
        Span<byte> encrypted = stackalloc byte[2 * SemiblockSize];

        for (int j = 0; j < 6; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                a.CopyTo(block2);
                r.AsSpan((i - 1) * SemiblockSize, SemiblockSize).CopyTo(block2[SemiblockSize..]);

                aes.EncryptEcb(block2, encrypted, PaddingMode.None);

                // A = MSB(64, B) XOR t, where t = (n * j) + i, encoded big-endian.
                ulong t = ((ulong)n * (ulong)j) + (ulong)i;
                ulong msb = BinaryPrimitives.ReadUInt64BigEndian(encrypted[..SemiblockSize]);
                BinaryPrimitives.WriteUInt64BigEndian(a, msb ^ t);

                // R[i] = LSB(64, B)
                encrypted[SemiblockSize..].CopyTo(r.AsSpan((i - 1) * SemiblockSize, SemiblockSize));
            }
        }

        a.CopyTo(output);
        r.CopyTo(output.AsSpan(SemiblockSize));
        return output;
    }
}
