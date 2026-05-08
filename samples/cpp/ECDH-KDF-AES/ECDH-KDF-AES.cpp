// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate two ECDH public/private key pairs. (Each key pair represents a
//    separate party: "Alice" (party 1) and "Bob" (party 2))
// 2. Perform ECDH key exchange, to exchange public keys between the two
//    parties, and generate a shared secret.
// 3. Use HKDF to derive the same AES key (using the shared secret) for both
//    parties.
// 4. Perform AES encryption and decryption to verify that the two derived
//    AES keys are identical.
//
// This scenario shows one way to utilize the AziHSM to establish a secure
// communication channel between two parties. Even though both parties are
// represented within the same user-space process in this demonstration, this
// scenario can be applied to two completely separate/isolated parties to
// securely communicate with one another.
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

#include <iostream>
#include <vector>
#include <string>

#include <windows.h>
#include <ncrypt.h>

#include <wil/resource.h>
#include <wil/result.h>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"
#include "Utils/CryptoUtils.h"

#define AES_GCM_AAD_LEN 32

// Helper enum used to differentiate between the supported AES modes for key
// derivation by the AziHSM.
enum class AesMode
{
    CBC,
    GCM
};

// ============================= NCrypt Helpers ============================= //
// Helper function that invokes AziHSM (via NCrypt) to generate an ECC key pair.
HRESULT create_ecdh_key(_In_ const wil::unique_ncrypt_prov &provider,
                        _In_ PCWSTR ecc_curve_name,
                        _In_ size_t ecc_curve_name_len,
                        _Out_ wil::unique_ncrypt_key &result)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, provider.get() == 0, "Invalid provider handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, ecc_curve_name == nullptr || ecc_curve_name_len == 0, "ECC curve name must not be empty");

    // Create an ECDH key with no flags and no key name
    RETURN_IF_FAILED_MSG(NCryptCreatePersistedKey(
                             provider.get(),
                             result.put(),
                             BCRYPT_ECDH_ALGORITHM,
                             NULL,
                             0,
                             0),
                         "Failed NCryptCreatePersistedKey for ECDH");

    // Set the key's ECC curve name property to use the provided curve
    RETURN_IF_FAILED_MSG(NCryptSetProperty(
                             result.get(),
                             NCRYPT_ECC_CURVE_NAME_PROPERTY,
                             (PBYTE)ecc_curve_name,
                             (DWORD)ecc_curve_name_len,
                             0),
                         "Failed NCryptSetProperty for ECC curve");

    // Finish the key creation process with `NCryptFinalizeKey()`
    RETURN_IF_FAILED_MSG(NCryptFinalizeKey(result.get(), 0), "Failed NCryptFinalizeKey for ECDH");

    return S_OK;
}

// Helper function that invokes AziHSM (via NCrypt) to export an ECDH key.
HRESULT export_ecdh_key(_In_ const wil::unique_ncrypt_key &key,
                        _Out_ std::vector<BYTE> &result)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, key.get() == 0, "Invalid key handle");

    DWORD buffer_len = 0;
    // Invoke `NCryptExportKey()` once, to determine the number of bytes required
    RETURN_IF_FAILED_MSG(NCryptExportKey(
                             key.get(),
                             NULL,
                             BCRYPT_ECCPUBLIC_BLOB,
                             NULL,
                             NULL,
                             0,
                             &buffer_len,
                             0),
                         "Failed 1st NCryptExportKey");
    RETURN_HR_IF_MSG(E_UNEXPECTED, buffer_len == 0, "Exported ECDH public key size must be non-zero");

    // Allocate a buffer and invoke `NCryptExportKey()` a second time
    std::vector<BYTE> buffer(buffer_len);
    RETURN_IF_FAILED_MSG(NCryptExportKey(
                             key.get(),
                             NULL,
                             BCRYPT_ECCPUBLIC_BLOB,
                             NULL,
                             buffer.data(),
                             (DWORD)buffer.size(),
                             &buffer_len,
                             0),
                         "Failed 2nd NCryptExportKey");

    result = std::move(buffer);
    return S_OK;
}

// Helper function that invokes AziHSM (via NCrypt) to import a public ECDH key.
HRESULT import_ecdh_key(_In_ const wil::unique_ncrypt_prov &provider,
                        _In_ const std::vector<BYTE> &buffer,
                        _Out_ wil::unique_ncrypt_key &result)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, provider.get() == 0, "Invalid provider handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, buffer.empty(), "ECDH public key buffer must not be empty");

    RETURN_IF_FAILED_MSG(NCryptImportKey(
                             provider.get(),
                             NULL,
                             BCRYPT_ECCPUBLIC_BLOB,
                             NULL,
                             result.put(),
                             (PBYTE)buffer.data(),
                             (DWORD)buffer.size(),
                             0),
                         "Failed NCryptImportKey for ECDH");

    return S_OK;
}

// Helper function that invokes AziHSM (via NCrypt) to generate a secret from ECDH keys.
HRESULT generate_secret(_In_ const wil::unique_ncrypt_key &private_ecdh_key,
                        _In_ const wil::unique_ncrypt_key &public_ecdh_key,
                        _Out_ wil::unique_ncrypt_secret &result)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, private_ecdh_key.get() == 0 || public_ecdh_key.get() == 0, "ECDH key handles must be valid");

    RETURN_IF_FAILED_MSG(NCryptSecretAgreement(
                             private_ecdh_key.get(),
                             public_ecdh_key.get(),
                             result.put(),
                             0),
                         "Failed NCryptSecretAgreement");

    return S_OK;
}

// Helper function that invokes AziHSM (via NCrypt) to derive an AES key using HKDF.
HRESULT derive_aes_key_hkdf(_In_ const wil::unique_ncrypt_prov &provider,
                            _In_ const wil::unique_ncrypt_secret &secret,
                            _In_ size_t key_bit_len,
                            _In_ PCWSTR hash_alg,
                            _In_ size_t hash_alg_len,
                            _In_z_ const wchar_t *info,
                            _In_ const size_t info_len,
                            _In_z_ const wchar_t *salt,
                            _In_ const size_t salt_len,
                            _In_ const AesMode aes_mode,
                            _Out_ wil::unique_ncrypt_key &result)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, provider.get() == 0, "Invalid provider handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, secret.get() == 0, "Invalid shared secret handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, hash_alg == nullptr || hash_alg_len == 0, "Hash algorithm buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, info == nullptr || info_len == 0, "HKDF info buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, salt == nullptr || salt_len == 0, "HKDF salt buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, aes_mode == AesMode::CBC && key_bit_len == 0, "AES-CBC key bit length must be non-zero");

    // Using HKDF requires using the HKDF algorithm identifier when invoking NCrypt.
    PCWSTR kdf_alg = BCRYPT_HKDF_ALGORITHM;

    // Select a chaining mode for the derived AES key.
    PBYTE chaining_mode = (PBYTE)BCRYPT_CHAIN_MODE_CBC;
    if (aes_mode == AesMode::GCM)
    {
        chaining_mode = (PBYTE)BCRYPT_CHAIN_MODE_GCM;
    }

    // Before calling `NCryptDeriveKey()`, we need to establish an array of
    // `BCryptBuffer` objects, which we'll pass into `NCryptDeriveKey()` as parameters.
    const size_t param_buffers_len = 4;
    BCryptBuffer param_buffers[param_buffers_len];

    // HASH ALGORITHM: this will tell AziHSM which hashing algorithm we want to use for key derivation.
    param_buffers[0].BufferType = KDF_HASH_ALGORITHM;
    param_buffers[0].cbBuffer = (ULONG)hash_alg_len;
    param_buffers[0].pvBuffer = (PVOID)hash_alg;

    // INFO: The HKDF Info is a custom string that is factored into the key derivation process.
    param_buffers[1].BufferType = KDF_HKDF_INFO;
    param_buffers[1].cbBuffer = (ULONG)info_len * sizeof(wchar_t);
    param_buffers[1].pvBuffer = (PVOID)info;

    // SALT: The HKDF Salt plays a similar role to the HKDF Info.
    param_buffers[2].BufferType = KDF_HKDF_SALT;
    param_buffers[2].cbBuffer = (ULONG)salt_len * sizeof(wchar_t);
    param_buffers[2].pvBuffer = (PVOID)salt;

    // KEY BIT LENGTH: Lastly, we need to specify the number of bits we want our derived AES key to be.
    uint32_t key_bit_length = (uint32_t)key_bit_len;
    if (aes_mode == AesMode::GCM)
    {
        // If we're using AES-GCM, force a 256-bit key length (this is the only
        // supported key length for AES-GCM by AziHSM).
        key_bit_length = 256;
    }
    param_buffers[3].BufferType = KDF_KEYBITLENGTH;
    param_buffers[3].cbBuffer = (ULONG)sizeof(uint32_t);
    param_buffers[3].pvBuffer = (PVOID)&key_bit_length;

    // Finally, set up a `BCryptBufferDesc` object to contain the array of `BCryptBuffer` objects.
    BCryptBufferDesc param_list;
    param_list.ulVersion = NCRYPTBUFFER_VERSION;
    param_list.cBuffers = (ULONG)param_buffers_len;
    param_list.pBuffers = (PBCryptBuffer)param_buffers;

    // Now invoke `NCryptDeriveKey()` once, to determine how many bytes we need to store the result.
    ULONG derived_key_buffer_len = 0;
    RETURN_IF_FAILED_MSG(NCryptDeriveKey(
                             secret.get(),
                             kdf_alg,
                             &param_list,
                             NULL,
                             0,
                             &derived_key_buffer_len,
                             0),
                         "Failed 1st NCryptDeriveKey");
    RETURN_HR_IF_MSG(E_UNEXPECTED, derived_key_buffer_len == 0, "Derived key buffer length must be non-zero");

    // Allocate a buffer and invoke `NCryptDeriveKey()` a second time
    // The AziHSM's return data from `NCryptDeriveKey()` is different than
    // other NCrypt Providers. Instead of returning the derived key's raw data
    // in the output buffer, the AziHSM instead returns a Key Handle in the
    // output buffer.
    //
    // This is done to ensure the derived key does not leave the trusted,
    // secure hardware environment of the physical AziHSM device.
    //
    // The returned key handle can then be re-imported into the AziHSM via
    // `NCryptImportKey()` in order to use it for encryption operations. We
    // will do this now.
    std::vector<BYTE> derived_key_buffer(derived_key_buffer_len);
    RETURN_IF_FAILED_MSG(NCryptDeriveKey(
                             secret.get(),
                             kdf_alg,
                             &param_list,
                             derived_key_buffer.data(),
                             (DWORD)derived_key_buffer.size(),
                             &derived_key_buffer_len,
                             0),
                         "Failed 2nd NCryptDeriveKey");
    RETURN_HR_IF_MSG(E_UNEXPECTED,
                     derived_key_buffer_len == 0 || derived_key_buffer_len > derived_key_buffer.size(),
                     "Invalid derived key buffer length returned: %lu",
                     derived_key_buffer_len);
    derived_key_buffer.resize(derived_key_buffer_len);

    RETURN_IF_FAILED_MSG(NCryptImportKey(
                             provider.get(),
                             NULL,
                             AZIHSM_DERIVED_KEY_IMPORT_BLOB_NAME,
                             NULL,
                             result.put(),
                             derived_key_buffer.data(),
                             (DWORD)derived_key_buffer_len,
                             NCRYPT_DO_NOT_FINALIZE_FLAG),
                         "Failed NCryptImportKey for derived key");

    // Count the number of bytes in the chaining mode string.
    size_t chaining_mode_len = 0;
    RETURN_IF_FAILED_MSG(count_wide_string_bytes((PCWSTR)chaining_mode, &chaining_mode_len), "Failed to get chaining mode length");

    // Set the key's chaining mode depending on the provided `aes_mode` parameter.
    RETURN_IF_FAILED_MSG(NCryptSetProperty(
                             result.get(),
                             NCRYPT_CHAINING_MODE_PROPERTY,
                             chaining_mode,
                             (DWORD)chaining_mode_len,
                             0),
                         "Failed NCryptSetProperty for chaining mode");
    printf("Set AES key chaining mode to: %ls.\n",
           (aes_mode == AesMode::GCM) ? BCRYPT_CHAIN_MODE_GCM : BCRYPT_CHAIN_MODE_CBC);

    // Finalize the key:
    RETURN_IF_FAILED_MSG(NCryptFinalizeKey(result.get(), 0), "Failed NCryptFinalizeKey for derived key");
    printf("Finalized AES key successfully.\n");

    return S_OK;
}

// Helper function that derives an AES key from the provided secret handle.
HRESULT derive_aes_key(_In_ const wil::unique_ncrypt_prov &provider,
                       _In_ const wil::unique_ncrypt_secret &secret,
                       _In_ size_t key_bit_len,
                       _In_ PCWSTR hash_alg,
                       _In_ size_t hash_alg_len,
                       _In_ AesMode aes_mode,
                       _Out_ wil::unique_ncrypt_key &result)
{
    // Define parameters used by HKDF: the info and salt.
    // Both of these parameters influence the resulting derived key. We want
    // Alice and Bob (our two parties) to derive the *same* AES key, so we
    // choose to use constant values here.
    const wchar_t *hkdf_info = L"info";
    const wchar_t *hkdf_salt = L"salt";
    size_t hkdf_info_len = 0;
    size_t hkdf_salt_len = 0;
    RETURN_IF_FAILED_MSG(get_wide_string_len(hkdf_info, &hkdf_info_len), "Failed to get HKDF info length");
    RETURN_IF_FAILED_MSG(get_wide_string_len(hkdf_salt, &hkdf_salt_len), "Failed to get HKDF salt length");

    // Invoke the HKDF-specific helper function.
    RETURN_IF_FAILED_MSG(derive_aes_key_hkdf(
                             provider,
                             secret,
                             key_bit_len,
                             hash_alg,
                             hash_alg_len,
                             hkdf_info,
                             hkdf_info_len,
                             hkdf_salt,
                             hkdf_salt_len,
                             aes_mode,
                             result),
                         "Failed derive_aes_key_hkdf");

    return S_OK;
}

// Helper function that encrypts plaintext using AES-CBC.
// iv will be modified
HRESULT encrypt_aes_cbc(_In_ const wil::unique_ncrypt_key &key,
                        _In_ const std::vector<BYTE> &plaintext,
                        _Inout_ std::vector<BYTE> &iv,
                        _Out_ std::vector<BYTE> &outCiphertext)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, key.get() == 0, "Invalid key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, plaintext.empty(), "Plaintext buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, iv.size() != 16, "AES-CBC IV must be 16 bytes, got %zu", iv.size());

    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.pbIV = (PBYTE)iv.data();
    pinfo.cbIV = (ULONG)iv.size();
    pinfo.pbOtherInfo = NULL;
    pinfo.cbOtherInfo = 0;
    pinfo.dwFlags = 0;

    DWORD ciphertext_len = 0;
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
                             key.get(),
                             (PBYTE)plaintext.data(),
                             (DWORD)plaintext.size(),
                             &pinfo,
                             NULL,
                             0,
                             &ciphertext_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 1st NCryptEncrypt");

    std::vector<BYTE> ciphertext(ciphertext_len);
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
                             key.get(),
                             (PBYTE)plaintext.data(),
                             (DWORD)plaintext.size(),
                             &pinfo,
                             ciphertext.data(),
                             (DWORD)ciphertext.size(),
                             &ciphertext_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 2nd NCryptEncrypt");

    outCiphertext = std::move(ciphertext);
    return S_OK;
}

// Helper function that decrypts ciphertext using AES-CBC.
// iv will be modified
HRESULT decrypt_aes_cbc(_In_ const wil::unique_ncrypt_key &key,
                        _In_ const std::vector<BYTE> &ciphertext,
                        _Inout_ std::vector<BYTE> &iv,
                        _Out_ std::vector<BYTE> &outPlaintext)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, key.get() == 0, "Invalid key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, ciphertext.empty(), "Ciphertext buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, iv.size() != 16, "AES-CBC IV must be 16 bytes, got %zu", iv.size());

    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.pbIV = (PBYTE)iv.data();
    pinfo.cbIV = (ULONG)iv.size();
    pinfo.pbOtherInfo = NULL;
    pinfo.cbOtherInfo = 0;
    pinfo.dwFlags = 0;

    DWORD plaintext_len = 0;
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
                             key.get(),
                             (PBYTE)ciphertext.data(),
                             (DWORD)ciphertext.size(),
                             &pinfo,
                             NULL,
                             0,
                             &plaintext_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 1st NCryptDecrypt");

    std::vector<BYTE> plaintext(plaintext_len);
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
                             key.get(),
                             (PBYTE)ciphertext.data(),
                             (DWORD)ciphertext.size(),
                             &pinfo,
                             plaintext.data(),
                             (DWORD)plaintext.size(),
                             &plaintext_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 2nd NCryptDecrypt");

    outPlaintext = std::move(plaintext);
    return S_OK;
}

// ================================== Main ================================== //
// Examines the command-line arguments and determines which AES mode to use for
// key derivation and encryption/decryption in this sample.
AesMode parse_aes_mode(_In_ int argc, _In_reads_(argc) char **argv)
{
    if (argc >= 2)
    {
        std::string parsed(argv[1]);

        if (parsed == "gcm")
        {
            return AesMode::GCM;
        }

        if (parsed == "cbc")
        {
            return AesMode::CBC;
        }
    }
    // Default to AES-GCM
    return AesMode::GCM;
}

// Main function. Program execution begins and ends here.
int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    try
    {
        set_wil_log_callback();

        printf("AziHSM Demonstration: ECDH Generate --> ECDH Exchange --> KDF AES --> AES Enc/Dec\n");
        printf("=================================================================================\n");

        // Parse the AES mode to be used from the command-line arguments.
        AesMode aes_mode = parse_aes_mode(argc, argv);

        printf("Keys will be derived using HKDF.\n");
        printf("An %s key will be derived and used for encryption & decryption.\n",
               (aes_mode == AesMode::GCM) ? "AES-GCM" : "AES-CBC");

        // Open a handle to the AziHSM via the NCrypt API.
        wil::unique_ncrypt_prov provider;
        RETURN_IF_FAILED_MSG(NCryptOpenStorageProvider(provider.put(), AZIHSM_KSP_NAME, 0), "Failed NCryptOpenStorageProvider");
        printf("Opened NCrypt Storage Provider handle: 0x%08x\n", (int)provider.get());

        // --------------- Step 1 - Generate ECDH Key Pairs (Alice & Bob) --------------- //
        printf("\nStep 1: Generate ECDH Key Pairs for Alice and Bob"
               "\n-------------------------------------------------\n");

        // Generate Alice's ECDH key pair
        PCWSTR curve_name = BCRYPT_ECC_CURVE_NISTP256;
        size_t curve_name_len = 0;
        RETURN_IF_FAILED_MSG(get_wide_string_len(curve_name, &curve_name_len), "Failed to get curve name length");

        wil::unique_ncrypt_key alice_key;
        RETURN_IF_FAILED_MSG(create_ecdh_key(provider, curve_name, curve_name_len * sizeof(wchar_t), alice_key), "Failed to create Alice's ECDH key");
        printf("Generated Alice's ECDH key pair. Key handle: 0x%08x\n", (int)alice_key.get());

        // Generate Bob's ECDH key pair
        wil::unique_ncrypt_key bob_key;
        RETURN_IF_FAILED_MSG(create_ecdh_key(provider, curve_name, curve_name_len * sizeof(wchar_t), bob_key), "Failed to create Bob's ECDH key");
        printf("Generated Bob's ECDH key pair. Key handle: 0x%08x\n", (int)bob_key.get());

        // --------------- Step 2 - Export & Exchange Public Keys --------------- //
        printf("\nStep 2: Export and Exchange Public Keys"
               "\n---------------------------------------\n");

        // Export Alice's public key
        std::vector<BYTE> alice_public_key;
        RETURN_IF_FAILED_MSG(export_ecdh_key(alice_key, alice_public_key), "Failed to export Alice's public key");
        printf("Exported Alice's public key: %zu bytes\n", alice_public_key.size());

        // Export Bob's public key
        std::vector<BYTE> bob_public_key;
        RETURN_IF_FAILED_MSG(export_ecdh_key(bob_key, bob_public_key), "Failed to export Bob's public key");
        printf("Exported Bob's public key: %zu bytes\n", bob_public_key.size());

        // Import Bob's public key for Alice to use
        wil::unique_ncrypt_key alice_imported_bob_key;
        RETURN_IF_FAILED_MSG(import_ecdh_key(provider, bob_public_key, alice_imported_bob_key), "Failed to import Bob's key for Alice");

        // Import Alice's public key for Bob to use
        wil::unique_ncrypt_key bob_imported_alice_key;
        RETURN_IF_FAILED_MSG(import_ecdh_key(provider, alice_public_key, bob_imported_alice_key), "Failed to import Alice's key for Bob");

        // --------------- Step 3 - Generate Shared Secrets --------------- //
        printf("\nStep 3: Generate Shared Secrets"
               "\n-------------------------------\n");

        // Alice generates shared secret using her private key and Bob's public key
        wil::unique_ncrypt_secret alice_secret;
        RETURN_IF_FAILED_MSG(generate_secret(alice_key, alice_imported_bob_key, alice_secret), "Failed to generate Alice's secret");
        printf("Alice generated shared secret. Handle: 0x%08x\n", (int)alice_secret.get());

        // Bob generates shared secret using his private key and Alice's public key
        wil::unique_ncrypt_secret bob_secret;
        RETURN_IF_FAILED_MSG(generate_secret(bob_key, bob_imported_alice_key, bob_secret), "Failed to generate Bob's secret");
        printf("Bob generated shared secret. Handle: 0x%08x\n", (int)bob_secret.get());

        // --------------- Step 4 - Derive AES Keys from Shared Secrets --------------- //
        printf("\nStep 4: Derive AES Keys using HKDF"
               "\n----------------------------------\n");

        // Prepare derivation parameters
        // Demo the generation of a 256-bit keys
        size_t key_bit_len = 256;
        PCWSTR hash_alg = BCRYPT_SHA256_ALGORITHM;
        size_t hash_alg_len = 0;
        RETURN_IF_FAILED_MSG(count_wide_string_bytes(hash_alg, &hash_alg_len), "Failed to get hash algorithm length");

        // Alice derives AES key
        wil::unique_ncrypt_key alice_aes_key;
        RETURN_IF_FAILED_MSG(derive_aes_key(provider, alice_secret, key_bit_len, hash_alg, hash_alg_len, aes_mode, alice_aes_key), "Failed to derive Alice's AES key");
        printf("Alice derived AES key. Handle: 0x%08x\n", (int)alice_aes_key.get());

        // Bob derives AES key
        wil::unique_ncrypt_key bob_aes_key;
        RETURN_IF_FAILED_MSG(derive_aes_key(provider, bob_secret, key_bit_len, hash_alg, hash_alg_len, aes_mode, bob_aes_key), "Failed to derive Bob's AES key");
        printf("Bob derived AES key. Handle: 0x%08x\n", (int)bob_aes_key.get());

        // --------------- Step 5 - Test Encryption & Decryption --------------- //
        printf("\nStep 5: Test Encryption and Decryption"
               "\n--------------------------------------\n");

        // Generate test plaintext
        size_t plaintext_len = 64;
        std::vector<BYTE> plaintext(plaintext_len);
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(plaintext.data(), plaintext.size())), "Failed to generate plaintext");
        std::cout << "Original plaintext:\n\t" << buffer_to_hex(plaintext.data(), plaintext.size()) << std::endl;

        if (aes_mode == AesMode::GCM)
        {
            // Test AES-GCM
            // For AES-GCM encryption, the AziHSM device will generate a random IV and return it to the caller.
            // The caller must provide a buffer filled with zeroes; AziHSM will check and fill it generated IV.
            std::vector<BYTE> iv(AZIHSM_AES_GCM_IV_LENGTH_BYTES, 0);

            // Generate AAD
            std::vector<BYTE> aad(AES_GCM_AAD_LEN);
            RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(aad.data(), aad.size())), "Failed to generate AAD");

            // Alice encrypts with her key
            std::vector<BYTE> tag, ciphertext;
            RETURN_IF_FAILED_MSG(encrypt_aes_gcm(alice_aes_key.get(), plaintext, aad, iv, tag, ciphertext), "Failed Alice GCM encryption");
            std::cout << "Ciphertext:\n\t" << buffer_to_hex(ciphertext.data(), ciphertext.size()) << std::endl;
            std::cout << "Generated IV:\n\t" << buffer_to_hex(iv.data(), iv.size()) << std::endl;

            // Bob decrypts with his key
            std::vector<BYTE> decrypted;
            RETURN_IF_FAILED_MSG(decrypt_aes_gcm(bob_aes_key.get(), ciphertext, aad, iv, tag, decrypted), "Failed Bob GCM decryption");
            std::cout << "Decrypted plaintext:\n\t" << buffer_to_hex(decrypted.data(), decrypted.size()) << std::endl;

            // Verify match
            RETURN_HR_IF_MSG(E_UNEXPECTED, plaintext != decrypted, "Decrypted data does not match original plaintext");
            printf("AES-GCM encryption/decryption test PASSED!\n");
        }
        else
        {
            // Test AES-CBC
            // Create random 128-bit IV for AES-CBC
            std::vector<BYTE> iv(16);
            RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(iv.data(), iv.size())), "Failed to generate IV");

            std::vector<BYTE> iv_copy(iv);

            // Alice encrypts with her key
            std::vector<BYTE> ciphertext;
            RETURN_IF_FAILED_MSG(encrypt_aes_cbc(alice_aes_key, plaintext, iv, ciphertext), "Failed Alice CBC encryption");
            std::cout << "Ciphertext:\n\t" << buffer_to_hex(ciphertext.data(), ciphertext.size()) << std::endl;

            // Bob decrypts with his key
            std::vector<BYTE> decrypted;
            RETURN_IF_FAILED_MSG(decrypt_aes_cbc(bob_aes_key, ciphertext, iv_copy, decrypted), "Failed Bob CBC decryption");
            std::cout << "Decrypted plaintext:\n\t" << buffer_to_hex(decrypted.data(), decrypted.size()) << std::endl;

            // Verify match
            RETURN_HR_IF_MSG(E_UNEXPECTED, plaintext != decrypted, "Decrypted data does not match original plaintext");
            printf("AES-CBC encryption/decryption test PASSED!\n");
        }

        printf("\nECDH Key Exchange + HKDF + AES Encryption Demo completed successfully!\n");
        return S_OK;
    }
    catch (const std::exception &ex)
    {
        fprintf(stderr, "Unhandled exception in ECDH-KDF-AES sample: %s\n", ex.what());
        return E_FAIL;
    }
    catch (...)
    {
        fprintf(stderr, "Unhandled unknown exception in ECDH-KDF-AES sample\n");
        return E_FAIL;
    }
}
