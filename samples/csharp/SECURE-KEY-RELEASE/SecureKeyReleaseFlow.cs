// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// The reusable Secure Key Release flow.
//
// Secure Key Release lets a workload move a key from Azure Key Vault into the
// AziHSM without the key material ever being visible to the guest:
//
//   1. The Guest Attestation Library attests the AziHSM's built-in import key
//      to Microsoft Azure Attestation (MAA), which returns a signed token.
//   2. Azure Key Vault is asked to release the key, presenting the MAA token as
//      proof. AKV returns the key wrapped for that specific AziHSM device.
//   3. The wrapped blob is imported into the AziHSM.

using System.Text.Json;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using AziHsm.Samples.Common;
using AziHsm.Samples.Common.Interop;
using KeyType = AziHsm.Samples.Common.KeyType;

namespace AziHsm.Samples.SecureKeyRelease;

/// <summary>Describes a key that Azure Key Vault released.</summary>
/// <param name="KeyBlob">The wrapped key blob (PKCS#11 <c>CKM_RSA_AES_KEY_WRAP</c> format).</param>
/// <param name="KeyType">Whether the released key is RSA or EC.</param>
/// <param name="KeySize">The key size: 2048-4096 for RSA, 256-521 for EC.</param>
internal readonly record struct ReleasedKey(byte[] KeyBlob, KeyType KeyType, int KeySize);

internal static class SecureKeyReleaseFlow
{
    /// <summary>
    /// Azure Key Vault wraps released keys with OAEP over SHA-1.
    /// </summary>
    private const string AkvPaddingAlgorithm = NCryptConstants.NCRYPT_SHA1_ALGORITHM;

    /// <summary>
    /// Runs the full Secure Key Release flow and imports the released key into
    /// the AziHSM.
    /// </summary>
    /// <param name="provider">A handle to the opened AziHSM provider.</param>
    /// <param name="importKey">A handle to the AziHSM built-in import/unwrapping key.</param>
    /// <param name="payload">
    /// A JSON object (as a string) containing the claims to include in the MAA
    /// token. MAA echoes this payload back in the token after a successful
    /// attestation, so it can carry key metadata or any other custom claims.
    /// </param>
    /// <param name="maaEndpoint">
    /// The MAA endpoint URL, for example <c>https://mytenant.attest.azure.net</c>.
    /// </param>
    /// <param name="keyUrl">
    /// The key identifier in Azure Key Vault, for example
    /// <c>https://myvault.vault.azure.net/keys/mykey/1234...</c>.
    /// </param>
    /// <param name="clientId">
    /// The optional client ID of a user-assigned managed identity that has
    /// access to the key vault. Needed when the VM has more than one identity.
    /// </param>
    /// <param name="keyUsage">
    /// One of <c>NCRYPT_ALLOW_DECRYPT_FLAG</c>, <c>NCRYPT_ALLOW_SIGNING_FLAG</c>
    /// or <c>NCRYPT_ALLOW_KEY_IMPORT_FLAG</c>.
    /// </param>
    public static (NCryptKeyHandle Key, KeyType KeyType, int KeySize) Run(
        NCryptProviderHandle provider,
        NCryptKeyHandle importKey,
        string payload,
        string maaEndpoint,
        string keyUrl,
        string? clientId,
        uint keyUsage)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);
        ArgumentException.ThrowIfNullOrEmpty(maaEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(keyUrl);

        // Step 1: Attest the AziHSM's import key with MAA and get the MAA token.
        string maaToken = AttestationClient.AttestAziHsm(importKey, maaEndpoint, payload);
        Console.WriteLine("Done attest_import_key.");

        // Step 2: Ask Azure Key Vault to release the key, and get the wrapped blob.
        ReleasedKey released = ReleaseKey(keyUrl, maaToken, clientId);
        Console.WriteLine(
            $"Done release_key. wrapped key blob length: {released.KeyBlob.Length}. " +
            $"Key type: {(released.KeyType == KeyType.Rsa ? "RSA" : "EC")}. " +
            $"Key size: {released.KeySize}");

        // Step 3: Import the wrapped key into the AziHSM.
        NCryptKeyHandle importedKey = ImportKeyBlob(provider, importKey, released, keyUsage);
        Console.WriteLine("Done import_key_blob");

        return (importedKey, released.KeyType, released.KeySize);
    }

    /// <summary>
    /// Calls the Azure Key Vault key release API and parses the response.
    /// </summary>
    /// <remarks>
    /// The Azure SDK handles both authentication (through
    /// <see cref="DefaultAzureCredential"/>, which picks up the VM's managed
    /// identity) and the release request itself. The equivalent raw call is:
    /// <code>
    /// curl --location '&lt;key_url&gt;/release?api-version=7.3' \
    ///   --header 'Content-Type: application/json' \
    ///   --header 'Authorization: Bearer &lt;token&gt;' \
    ///   --data '{"nonce": "...", "target": "&lt;maa_token&gt;", "enc": "CKM_RSA_AES_KEY_WRAP"}'
    /// </code>
    /// </remarks>
    private static ReleasedKey ReleaseKey(string keyUrl, string maaToken, string? clientId)
    {
        KeyVaultKeyIdentifier keyIdentifier = new(new Uri(keyUrl));

        DefaultAzureCredentialOptions credentialOptions = new();
        if (!string.IsNullOrEmpty(clientId))
        {
            // Select a specific user-assigned managed identity. Needed when the
            // VM has more than one identity attached.
            credentialOptions.ManagedIdentityClientId = clientId;
        }

        KeyClient keyClient = new(keyIdentifier.VaultUri, new DefaultAzureCredential(credentialOptions));

        ReleaseKeyOptions options = new(keyIdentifier.Name, maaToken)
        {
            Version = keyIdentifier.Version,
            Nonce = GenerateNonce(),
            Algorithm = KeyExportEncryptionAlgorithm.CkmRsaAesKeyWrap,
        };

        ReleaseKeyResult result = keyClient.ReleaseKey(options);

        return ParseAkvJwt(result.Value);
    }

    /// <summary>
    /// Generates the nonce sent to Azure Key Vault.
    /// </summary>
    /// <remarks>
    /// TODO: You should generate a random nonce. A fixed value is used here for
    /// simplicity.
    /// </remarks>
    private static string GenerateNonce()
    {
        Console.Error.WriteLine("DO NOT USE FOR PRODUCTION: GenerateNonce used a fixed nonce.");

        // A nonce can be a short string of random characters.
        return "FIXED_NONCE";
    }

    /// <summary>
    /// Parses the JWT returned by Azure Key Vault and extracts the wrapped key
    /// blob along with the key type and size.
    /// </summary>
    /// <remarks>
    /// For simplicity, JWT signature verification is SKIPPED. Production code
    /// must verify the token with a proper JWT library before trusting its
    /// contents.
    ///
    /// The relevant claims are:
    ///   <c>response.key.key.key_hsm</c>  - base64url JSON holding the ciphertext
    ///   <c>response.key.key.kty</c>      - the key type ("RSA-HSM", "EC-HSM", ...)
    ///   <c>response.key.key.crv</c>      - the curve name, for EC keys
    ///   <c>response.key.attributes.key_size</c> - the key size, for RSA keys
    /// </remarks>
    private static ReleasedKey ParseAkvJwt(string jwt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);

        Console.Error.WriteLine("DO NOT USE FOR PRODUCTION: ParseAkvJwt skipped JWT verification.");

        string[] segments = jwt.Split('.');
        if (segments.Length < 3)
        {
            throw new InvalidDataException("Invalid JWT format in the AKV response");
        }

        using JsonDocument payload = JsonDocument.Parse(Base64UrlDecode(segments[1]));

        JsonElement keyObject = GetProperty(GetProperty(payload.RootElement, "response"), "key");
        JsonElement innerKeyObject = GetProperty(keyObject, "key");

        string keyTypeName = GetProperty(innerKeyObject, "kty").GetString()
            ?? throw new InvalidDataException("JWT payload has an empty 'response.key.key.kty' field");

        KeyType keyType = keyTypeName.StartsWith("rsa", StringComparison.OrdinalIgnoreCase)
            ? KeyType.Rsa
            : KeyType.Ecdsa;

        int keySize;
        if (keyType == KeyType.Rsa)
        {
            keySize = GetProperty(GetProperty(keyObject, "attributes"), "key_size").GetInt32();
        }
        else
        {
            string curve = GetProperty(innerKeyObject, "crv").GetString()
                ?? throw new InvalidDataException("JWT payload has an empty 'response.key.key.crv' field");

            keySize = curve switch
            {
                "P-256" => 256,
                "P-384" => 384,
                "P-521" => 521,
                _ => throw new InvalidDataException($"Invalid 'response.key.key.crv' field: {curve}"),
            };
        }

        // `key_hsm` is itself base64url-encoded JSON that holds the ciphertext.
        string keyHsmBase64 = GetProperty(innerKeyObject, "key_hsm").GetString()
            ?? throw new InvalidDataException("JWT payload has an empty 'response.key.key.key_hsm' field");

        using JsonDocument keyHsm = JsonDocument.Parse(Base64UrlDecode(keyHsmBase64));
        string ciphertextBase64 = GetProperty(keyHsm.RootElement, "ciphertext").GetString()
            ?? throw new InvalidDataException("key_hsm data has an empty 'ciphertext' field");

        return new ReleasedKey(Base64UrlDecode(ciphertextBase64), keyType, keySize);
    }

    /// <summary>
    /// Imports the key blob released by Azure Key Vault into the AziHSM.
    /// </summary>
    /// <remarks>
    /// AKV returns the raw PKCS#11 <c>CKM_RSA_AES_KEY_WRAP</c> payload, so the
    /// <c>BCRYPT_PKCS11_RSA_AES_WRAP_BLOB</c> header has to be prepended before
    /// it can be handed to <c>NCryptImportKey()</c>.
    /// </remarks>
    private static NCryptKeyHandle ImportKeyBlob(
        NCryptProviderHandle provider,
        NCryptKeyHandle importKey,
        ReleasedKey released,
        uint keyUsage)
    {
        if (released.KeyBlob.Length == 0)
        {
            throw new ArgumentException("Wrapped key blob must not be empty", nameof(released));
        }

        byte[] fullBlob = RsaWrapUtils.BuildPkcs11WrapBlob(released.KeyBlob, AkvPaddingAlgorithm);

        return CryptoUtils.ImportWrappedKey(
            provider, importKey, fullBlob, released.KeyType, released.KeySize, keyUsage);
    }

    private static JsonElement GetProperty(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value)
            ? value
            : throw new InvalidDataException($"JWT payload is missing the '{name}' field");

    /// <summary>
    /// Decodes an unpadded base64url string, the encoding used throughout JWTs.
    /// </summary>
    private static byte[] Base64UrlDecode(string value)
    {
        string base64 = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight((base64.Length + 3) / 4 * 4, '='));
    }
}
