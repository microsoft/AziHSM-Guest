// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate two ECDH public/private key pairs. (Each key pair represents a
//    separate party: "Alice" (party 1) and "Bob" (party 2))
// 2. Perform ECDH key exchange, to exchange public keys between the two
//    parties, and generate a shared secret.
// 3. Use KBKDF or HKDF to derive the same AES key (using the shared secret)
//    for both parties.
// 4. Perform AES-CBC encryption and decryption to verify that the two derived
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
#include <random>

// Use `WIN32_NO_STATUS` to prevent macro-redefinition warnings in `ntstatus.h`
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>
#include <ncrypt.h>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"

// Force the linking of the NCrypt library into this executable, so we can
// access NCrypt symbols in our code below:
#pragma comment(lib, "ncrypt.lib")

// Global settings to toggle between KBKDF and HKDF (By default, this program
// will use KBKDF.)
typedef enum _KDFType
{
    KDF_TYPE_KBKDF, // Key-Based Key Derivation Function
    KDF_TYPE_HKDF,  // HMAC-based Key Derivation Function
} KDFType;


// ============================= NCrypt Helpers ============================= //
// Helper function that invokes AziHSM (via NCrypt) to generate an ECC key
// pair.
static SECURITY_STATUS create_ecdh_key(NCRYPT_PROV_HANDLE provider,
                                       PCWSTR ecc_curve_name,
                                       NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;

    // Create an ECDH key with no flags and no key name
    NCRYPT_KEY_HANDLE key = NULL;
    status = NCryptCreatePersistedKey(
        provider,
        &key,
        BCRYPT_ECDH_ALGORITHM,
        NULL,
        0,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to generate ECDH key. "
                "NCryptCreatePersistedKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Set the key's ECC curve name property to use the provided curve
    status = NCryptSetProperty(
        key,
        NCRYPT_ECC_CURVE_NAME_PROPERTY,
        (PBYTE) ecc_curve_name,
        (DWORD) wcslen(ecc_curve_name) * sizeof(wchar_t),
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to set ECC Curve Name property for ECDH key. "
                "NCryptSetProperty returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Finish the key creation process with `NCryptFinalizeKey()`
    status = NCryptFinalizeKey(key, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to finalize creation of ECDH key. "
                "NCryptFinalizeKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // Success; update the return pointer and set a successful return status.
    // Set `key` back to NULL, to move ownership of the key handle to
    // `*result`.
    *result = key;
    key = NULL;
    status = S_OK;

cleanup:
    SECURITY_STATUS exit_status = status;
    
    // If the key was not set back to zero, then something went wrong above and
    // we need to free the key before returning.
    if (key != NULL)
    {
        status = NCryptFreeObject(key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free ECDH key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
    }

    return exit_status;
}

// Helper function that invokes AziHSM (via NCrypt) to export an ECDH key,
// accessible through the given NCrypt key handle.
static SECURITY_STATUS export_ecdh_key(NCRYPT_KEY_HANDLE key,
                                       BYTE** result,
                                       DWORD* result_len)
{
    SECURITY_STATUS status = S_OK;
    BYTE* buffer = NULL;
    DWORD buffer_len = NULL;

    // Invoke `NCryptExportKey()` once, to determine the number of bytes
    // required to store the exported key
    status = NCryptExportKey(
        key,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        NULL,
        0,
        &buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to export ECDH private key. "
                "NCryptExportKey (call #1) returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // Allocate a buffer of the specified size, then invoke `NCryptExportKey()`
    // a second time, to store the exported key.
    buffer = new BYTE[buffer_len];
    status = NCryptExportKey(
        key,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        (PBYTE) buffer,
        buffer_len,
        &buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to export ECDH private key. "
                "NCryptExportKey (call #2) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Success; update the return pointers to point at the buffer containing
    // the exported public key, and set a success status.
    // Reset `buffer` to be NULL, to transfer ownership of the memory to
    // `*result`.
    *result = buffer;
    *result_len = buffer_len;
    buffer = NULL;
    status = S_OK;
    
    // Label for cleaning up local resources on error.
cleanup:
    SECURITY_STATUS exit_status = status;

    // If the buffer was not reset back to NULL, then something went wrong
    // above and we need to free its memory before returning.
    if (buffer != NULL)
    {
        delete[] buffer;
    }

    return exit_status;
}

// Helper function that invokes AziHSM (via NCrypt) to import a public ECDH
// key. The resulting key handle is stored in `*result`.
static SECURITY_STATUS import_ecdh_key(NCRYPT_PROV_HANDLE provider,
                                       BYTE* buffer,
                                       DWORD buffer_len,
                                       NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;

    NCRYPT_KEY_HANDLE key = NULL;
    status = NCryptImportKey(
        provider,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        &key,
        (PBYTE) buffer,
        buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to import ECDH public key. "
                "NCryptImportKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // Success; set the return pointer and set a success status message.
    // Reset `key` to NULL, to transfer ownership of the key handle to
    // `*result`.
    *result = key;
    key = NULL;
    status = S_OK;

cleanup:
    SECURITY_STATUS exit_status = status;
    return exit_status;
}

// Helper function that invokes AziHSM (via NCrypt) with the handles to a
// private ECDH key and a public ECDH key to generate a secret.
// The resulting secret handle is stored in `*result`.
static SECURITY_STATUS generate_secret(NCRYPT_KEY_HANDLE private_ecdh_key,
                                       NCRYPT_KEY_HANDLE public_ecdh_key,
                                       NCRYPT_SECRET_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;

    NCRYPT_SECRET_HANDLE secret = NULL;
    status = NCryptSecretAgreement(
        private_ecdh_key,
        public_ecdh_key,
        &secret,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to generate a secret with both ECDH keys. "
                "NCryptSecretAgreement returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // Success; set the return pointer and set a success status message
    // Reset `secret` to NULL, to transfer ownership of the secret handle to
    // `*result`.
    *result = secret;
    secret = NULL;
    status = S_OK;

cleanup:
    SECURITY_STATUS exit_status = status;
    return exit_status;
}

// Helper function that invokes AziHSM (via NCrypt) with the given secret
// handle to derive an AES key, using KBKDF.
static SECURITY_STATUS derive_aes_key_kbkdf(NCRYPT_PROV_HANDLE provider,
                                            NCRYPT_SECRET_HANDLE secret,
                                            size_t key_bit_len,
                                            PCWSTR hash_alg,
                                            const wchar_t* context,
                                            const size_t context_len,
                                            const wchar_t* label,
                                            const size_t label_len,
                                            NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;
    NCRYPT_KEY_HANDLE key = NULL;
    
    // Using KBKDF requires using the SP800-108 HMAC in Counter Mode algorithm
    // identifier when invoking NCrypt.
    PCWSTR kdf_alg = BCRYPT_SP800108_CTR_HMAC_ALGORITHM;

    // Before calling `NCryptDeriveKey()`, we need to establish an array of
    // `BCryptBuffer` objects, which we'll pass into `NCryptDeriveKey()` as
    // parameters.
    const size_t param_buffers_len = 4;
    BCryptBuffer param_buffers[param_buffers_len];

    // HASH ALGORITHM: this will tell AziHSM which hashing algorithm we want to
    // use for key derivation.
    param_buffers[0].BufferType = KDF_HASH_ALGORITHM;
    param_buffers[0].cbBuffer = (ULONG) (wcslen(hash_alg) * sizeof(wchar_t));
    param_buffers[0].pvBuffer = (PVOID) hash_alg;
    
    // CONTEXT: The KBKDF Context is a custom string that is factored into the
    // key derivation process. If two keys are derived from the same secret,
    // but they have different context strings, the resulting derived key will
    // be different.
    param_buffers[1].BufferType = KDF_CONTEXT;
    param_buffers[1].cbBuffer = (ULONG) context_len * sizeof(wchar_t);
    param_buffers[1].pvBuffer = (PVOID) context;
    
    // LABEL: The KBKDF Label plays a similar role to the KBKDF Context. It is
    // a custom string that is factored into the key derivation process. If two
    // keys are derived from the same secret, *and* the same context, but they
    // have different label strings, the resulting derived key will be
    // different.
    param_buffers[2].BufferType = KDF_LABEL;
    param_buffers[2].cbBuffer = (ULONG) label_len * sizeof(wchar_t);
    param_buffers[2].pvBuffer = (PVOID) label;
    
    // KEY BIT LENGTH: Lastly, we need to specify the number of bits we want
    // our derived AES key to be.
    const uint32_t key_bit_length = (uint32_t) key_bit_len;
    param_buffers[3].BufferType = KDF_KEYBITLENGTH;
    param_buffers[3].cbBuffer = (ULONG) sizeof(uint32_t);
    param_buffers[3].pvBuffer = (PVOID) &key_bit_length;

    // Finally, set up a `BCryptBufferDesc` object to contain the array of
    // `BCryptBuffer` objects.
    BCryptBufferDesc param_list;
    param_list.ulVersion = NCRYPTBUFFER_VERSION;
    param_list.cBuffers = (ULONG) param_buffers_len;
    param_list.pBuffers = (PBCryptBuffer) param_buffers;

    BYTE* derived_key_buffer = NULL;
    ULONG derived_key_buffer_len = 0;

    // Now that our parameters are set up, we'll invoke `NCryptDeriveKey()`
    // once, to determine how many bytes we need to store the result.
    status = NCryptDeriveKey(
        secret,
        kdf_alg,
        &param_list,
        NULL,
        0,
        &derived_key_buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to derive AES key from secret using KBKDF. "
                "NCryptDeriveKey (call #1) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Allocate a buffer of the specified size, then invoke `NCryptDeriveKey()`
    // a second time, to store the output data.
    derived_key_buffer = new BYTE[derived_key_buffer_len];
    status = NCryptDeriveKey(
        secret,
        kdf_alg,
        &param_list,
        (PUCHAR) derived_key_buffer,
        derived_key_buffer_len,
        &derived_key_buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to derive AES key from secret using KBKDF. "
                "NCryptDeriveKey (call #2) returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
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

    // Invoke `NCryptImportKey()` with the `derived_key_buffer` variable used
    // above to store the result from `NCryptDeriveKey()`.
    status = NCryptImportKey(
        provider,
        NULL,
        AZIHSM_DERIVED_KEY_IMPORT_BLOB_NAME,
        NULL,
        &key,
        (PBYTE) derived_key_buffer,
        (DWORD) derived_key_buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to import KBKDF-derived AES key. "
                "NCryptImportKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // With that, we have successfully:
    //
    // 1. Derived an AES key from the provided secret.
    // 2. Imported the resulting key handle back into AziHSM.
    //
    // The AES key handle (`*result`) is now ready to be used for
    // encryption/decryption.
    
    // Update the return pointer, and reset `key` to be NULL, to transfer
    // ownership of the key handle to `*result`.
    *result = key;
    key = NULL;
    status = S_OK;
    
    // Label for cleaning up resources during a failure in the key derivation
    // process.
cleanup:
    SECURITY_STATUS exit_status = status;

    // Free the buffer used to store the results from `NCryptDeriveKey()`; we
    // no longer need it, now that we've re-imported the key
    delete[] derived_key_buffer;

    return exit_status;
}

// Helper function that invokes AziHSM (via NCrypt) with the given secret
// handle to derive an AES key, using HKDF.
static SECURITY_STATUS derive_aes_key_hkdf(NCRYPT_PROV_HANDLE provider,
                                           NCRYPT_SECRET_HANDLE secret,
                                           size_t key_bit_len,
                                           PCWSTR hash_alg,
                                           const wchar_t* info,
                                           const size_t info_len,
                                           const wchar_t* salt,
                                           const size_t salt_len,
                                           NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;
    NCRYPT_KEY_HANDLE key = NULL;

    // Using HKDF requires using the HKDF algorithm identifier when invoking
    // NCrypt.
    PCWSTR kdf_alg = BCRYPT_HKDF_ALGORITHM;

    // Before calling `NCryptDeriveKey()`, we need to establish an array of
    // `BCryptBuffer` objects, which we'll pass into `NCryptDeriveKey()` as
    // parameters.
    const size_t param_buffers_len = 4;
    BCryptBuffer param_buffers[param_buffers_len];

    // HASH ALGORITHM: this will tell AziHSM which hashing algorithm we want to
    // use for key derivation.
    param_buffers[0].BufferType = KDF_HASH_ALGORITHM;
    param_buffers[0].cbBuffer = (ULONG) (wcslen(hash_alg) * sizeof(wchar_t));
    param_buffers[0].pvBuffer = (PVOID) hash_alg;
    
    // INFO: The HKDF Info is a custom string that is factored into the key
    // derivation process. If two keys are derived from the same secret, but
    // they have different info strings, the resulting derived key will be
    // different.
    param_buffers[1].BufferType = KDF_HKDF_INFO;
    param_buffers[1].cbBuffer = (ULONG) info_len * sizeof(wchar_t);
    param_buffers[1].pvBuffer = (PVOID) info;
    
    // SALT: The HKDF Salt plays a similar role to the HKDF Info. It is a
    // custom string that is factored into the key derivation process. If two
    // keys are derived from the same secret, *and* the same info, but they
    // have different salt strings, the resulting derived key will be
    // different.
    param_buffers[2].BufferType = KDF_HKDF_SALT;
    param_buffers[2].cbBuffer = (ULONG) salt_len * sizeof(wchar_t);
    param_buffers[2].pvBuffer = (PVOID) salt;
    
    // KEY BIT LENGTH: Lastly, we need to specify the number of bits we want
    // our derived AES key to be.
    const uint32_t key_bit_length = (uint32_t) key_bit_len;
    param_buffers[3].BufferType = KDF_KEYBITLENGTH;
    param_buffers[3].cbBuffer = (ULONG) sizeof(uint32_t);
    param_buffers[3].pvBuffer = (PVOID) &key_bit_length;

    // Finally, set up a `BCryptBufferDesc` object to contain the array of
    // `BCryptBuffer` objects.
    BCryptBufferDesc param_list;
    param_list.ulVersion = NCRYPTBUFFER_VERSION;
    param_list.cBuffers = (ULONG) param_buffers_len;
    param_list.pBuffers = (PBCryptBuffer) param_buffers;

    BYTE* derived_key_buffer = NULL;
    ULONG derived_key_buffer_len = 0;

    // Now that our parameters are set up, we'll invoke `NCryptDeriveKey()`
    // once, to determine how many bytes we need to store the result.
    status = NCryptDeriveKey(
        secret,
        kdf_alg,
        &param_list,
        NULL,
        0,
        &derived_key_buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to derive AES key from secret using HKDF. "
                "NCryptDeriveKey (call #1) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Allocate a buffer of the specified size, then invoke `NCryptDeriveKey()`
    // a second time, to store the output data.
    derived_key_buffer = new BYTE[derived_key_buffer_len];
    status = NCryptDeriveKey(
        secret,
        kdf_alg,
        &param_list,
        (PUCHAR) derived_key_buffer,
        derived_key_buffer_len,
        &derived_key_buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to derive AES key from secret using HKDF. "
                "NCryptDeriveKey (call #2) returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
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

    // Invoke `NCryptImportKey()` with the `derived_key_buffer` variable used
    // above to store the result from `NCryptDeriveKey()`.
    status = NCryptImportKey(
        provider,
        NULL,
        AZIHSM_DERIVED_KEY_IMPORT_BLOB_NAME,
        NULL,
        &key,
        (PBYTE) derived_key_buffer,
        (DWORD) derived_key_buffer_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to import HKDF-derived AES key. "
                "NCryptImportKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // With that, we have successfully:
    //
    // 1. Derived an AES key from the provided secret.
    // 2. Imported the resulting key handle back into AziHSM.
    //
    // The AES key handle (`*result`) is now ready to be used for
    // encryption/decryption.
    
    // Update the return pointer, and reset `key` to be NULL, to transfer
    // ownership of the key handle to `*result`.
    *result = key;
    key = NULL;
    status = S_OK;
    
    // Label for cleaning up resources during a failure in the key derivation
    // process.
cleanup:
    SECURITY_STATUS exit_status = status;

    // Free the buffer used to store the results from `NCryptDeriveKey()`; we
    // no longer need it, now that we've re-imported the key
    delete[] derived_key_buffer;

    return exit_status;
}

// Helper function that differentiates between the two possible KDF types
// (KBKDF and HKDF) to derive an AES key.
// This function invokes the two helper functions defined above based on the
// provided `kdf` parameter:
//
// * `KDF_TYPE_KBKDF` --> `derive_aes_key_kbkdf()`
// * `KDF_TYPE_HKDF` --> `derive_aes_key_hkdf()`
static SECURITY_STATUS derive_aes_key(NCRYPT_PROV_HANDLE provider,
                                      NCRYPT_SECRET_HANDLE secret,
                                      size_t key_bit_len,
                                      PCWSTR hash_alg,
                                      KDFType kdf,
                                      NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;
    NCRYPT_KEY_HANDLE key = NULL;

    // Differentiate between the two possible KDF types:
    if (kdf == KDF_TYPE_KBKDF)
    {
        // Define parameters used by KBKDF: the context and label.
        // Both of these parameters influence the resulting derived key. We want
        // Alice and Bob (our two parties) to derive the *same* AES key, so we
        // choose to use constant values here.
        const wchar_t* kbkdf_context = L"ctx";
        const size_t kbkdf_context_len = wcslen(kbkdf_context);
        const wchar_t* kbkdf_label = L"enc,dec";
        const size_t kbkdf_label_len = wcslen(kbkdf_label);
        
        // Invoke the KBKDF-specific helper function.
        status = derive_aes_key_kbkdf(
            provider,
            secret,
            key_bit_len,
            hash_alg,
            kbkdf_context,
            kbkdf_context_len,
            kbkdf_label,
            kbkdf_label_len,
            &key
        );
        if (FAILED(status))
        {
            goto cleanup;
        }
        
        // On success, assign the key handle to the return pointer, and reset
        // `key` back to NULL, to transfer ownership.
        *result = key;
        key = NULL;
        status = S_OK;
    }
    else // kdf == KDF_TYPE_HKDF
    {
        // Define parameters used by HKDF: the info and salt.
        // Both of these parameters influence the resulting derived key. We want
        // Alice and Bob (our two parties) to derive the *same* AES key, so we
        // choose to use constant values here.
        const wchar_t* hkdf_info = L"info";
        const size_t hkdf_info_len = wcslen(hkdf_info);
        const wchar_t* hkdf_salt = L"salt";
        const size_t hkdf_salt_len = wcslen(hkdf_salt);
        
        // Invoke the HKDF-specific helper function.
        status = derive_aes_key_hkdf(
            provider,
            secret,
            key_bit_len,
            hash_alg,
            hkdf_info,
            hkdf_info_len,
            hkdf_salt,
            hkdf_salt_len,
            &key
        );
        if (FAILED(status))
        {
            goto cleanup;
        }
        
        // On success, assign the key handle to the return pointer, and reset
        // `key` back to 0, to transfer ownership.
        *result = key;
        key = NULL;
        status = S_OK;
    }

cleanup:
    SECURITY_STATUS exit_status = status;
    return exit_status;
}

// Helper function that invokes `NCryptEncrypt()` to encrypt the provided
// plaintext (using AES-CBC and the provided Initialization Vector).
//
// The resulting ciphertext is stored in a new, allocated buffer, whose address
// is stored in `*result`, and whose length is stored in `*result_len`.
static SECURITY_STATUS encrypt_aes_cbc(NCRYPT_KEY_HANDLE key,
                                       BYTE* plaintext,
                                       size_t plaintext_len,
                                       BYTE* iv,
                                       size_t iv_len,
                                       BYTE** result,
                                       size_t* result_len)
{
    SECURITY_STATUS status = S_OK;

    // Start by creating a padding information struct to pass into
    // `NCryptEncrypt()`.
    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.pbIV = (BYTE*) iv;
    pinfo.cbIV = (ULONG) iv_len;
    pinfo.pbOtherInfo = NULL;
    pinfo.cbOtherInfo = 0;
    pinfo.dwFlags = 0;
    
    BYTE* ciphertext = NULL;
    DWORD ciphertext_len = 0;

    // Call `NCryptEncrypt()` once, to determine the size of the buffer we'll
    // allocate to store the ciphertext.
    status = NCryptEncrypt(
        key,
        plaintext,
        (DWORD) plaintext_len,
        (VOID*) &pinfo,
        NULL,
        0,
        &ciphertext_len,
        NCRYPT_PAD_CIPHER_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to encrypt with AES-CBC. "
                "NCryptEncrypt (call #1) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Allocate a buffer for the encrypted data, using the size we just
    // received from the first call to `NCryptEncrypt()`.
    ciphertext = new BYTE[(size_t) ciphertext_len];

    // Call `NCryptEncrypt()` a second time to compute the ciphertext and store
    // the result in our buffer.
    status = NCryptEncrypt(
        key,
        plaintext,
        (DWORD) plaintext_len,
        (VOID*) &pinfo,
        ciphertext,
        ciphertext_len,
        &ciphertext_len,
        NCRYPT_PAD_CIPHER_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to encrypt with AES-CBC. "
                "NCryptEncrypt (call #2) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Store the ciphertext buffer, and its length, in the output parameters.
    // Reset `ciphertext` to be NULL, to transfer ownership of the buffer to
    // `*result`.
    *result = ciphertext;
    *result_len = (size_t) ciphertext_len;
    ciphertext = NULL;
    status = S_OK;
    
cleanup:
    SECURITY_STATUS exit_status = status;

    // If the ciphertext is still pointing at an allocated buffer, then
    // something went wrong above, and we need to free it before returning.
    if (ciphertext != NULL)
    {
        delete[] ciphertext;
    }

    return exit_status;
}

// Helper function that invokes `NCryptDecrypt()` to decrypt the provided
// ciphertext (using AES-CBC and the provided Initialization Vector).
//
// The resulting plaintext is stored in a new, allocated buffer, whose address
// is stored in `*result`, and whose length is stored in `*result_len`.
static SECURITY_STATUS decrypt_aes_cbc(NCRYPT_KEY_HANDLE key,
                                       BYTE* ciphertext,
                                       size_t ciphertext_len,
                                       BYTE* iv,
                                       size_t iv_len,
                                       BYTE** result,
                                       size_t* result_len)
{
    SECURITY_STATUS status = S_OK;

    // Start by creating a padding information struct to pass into
    // `NCryptDecrypt()`.
    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.pbIV = (BYTE*) iv;
    pinfo.cbIV = (ULONG) iv_len;
    pinfo.pbOtherInfo = NULL;
    pinfo.cbOtherInfo = 0;
    pinfo.dwFlags = 0;
    
    BYTE* plaintext = NULL;
    DWORD plaintext_len = 0;

    // Call `NCryptDecrypt()` once, to determine the size of the buffer we'll
    // allocate to store the plaintext.
    status = NCryptDecrypt(
        key,
        ciphertext,
        (DWORD) ciphertext_len,
        (VOID*) &pinfo,
        NULL,
        0,
        &plaintext_len,
        NCRYPT_PAD_CIPHER_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to decrypt with AES-CBC. "
                "NCryptDecrypt (call #1) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Allocate a buffer for the decrypted data, using the size we just
    // received from the first call to `NCryptDecrypt()`.
    plaintext = new BYTE[(size_t) plaintext_len];

    // Call `NCryptEncrypt()` a second time to compute the plaintext and store
    // the result in our buffer.
    status = NCryptDecrypt(
        key,
        ciphertext,
        (DWORD) ciphertext_len,
        (VOID*) &pinfo,
        plaintext,
        plaintext_len,
        &plaintext_len,
        NCRYPT_PAD_CIPHER_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to decrypt with AES-CBC. "
                "NCryptDecrypt (call #2) returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Store the plaintext buffer, and its length, in the output parameters.
    // Reset `plaintext` to be NULL, to transfer ownership of the buffer to
    // `*result`.
    *result = plaintext;
    *result_len = (size_t) plaintext_len;
    plaintext = NULL;
    status = S_OK;
    
cleanup:
    SECURITY_STATUS exit_status = status;

    // If `plaintext` still points to an allocated buffer, then something went
    // wrong above, and we need to free its memory before returning.
    if (plaintext != NULL)
    {
        delete[] plaintext;
    }

    return exit_status;
}


// ================================== Main ================================== //
// Helper function that determines which KDF (Key Derivation Function) to use
// during execution, based on the command-line arguments provided by the user.
static KDFType parse_kdf_type(int argc, char** argv)
{
    KDFType result = KDF_TYPE_KBKDF;
    
    // Iterate through each command-line argument (skipping the first, which is
    // the executable path) and look for either "KBKDF" or "HKDF". Convert
    // strings to lowercase to allow for case insensitive matches.
    for (int i = 1; i < argc; i++)
    {
        char* arg = argv[i];

        // Make a copy of the argument string, and convert it to lowercase
        size_t str_len = std::strlen(arg);
        char* str = new char[str_len + 1];
        for (size_t j = 0; j < str_len; j++)
        {
            str[j] = std::tolower(static_cast<unsigned char>(arg[j]));
        }
        str[str_len] = '\0';

        // Does the string match KBKDF or HKDF? If so, update the return value
        if (!strcmp(str, "kbkdf"))
        {
            result = KDF_TYPE_KBKDF;
        }
        else if (!strcmp(str, "hkdf"))
        {
            result = KDF_TYPE_HKDF;
        }

        delete[] str;
    }
    
    return result;
}

// Main function. Program execution begins and ends here.
int main(int argc, char** argv)
{
    printf("AziHSM Demonstration: ECDH Generate --> ECDH Exchange --> KDF AES --> AES-CBC Enc/Dec\n");
    printf("=====================================================================================\n");

    HRESULT status = S_OK;

    // Parse the command-line arguments to determine which of the two
    // AziHSM-supported KDFs (Key Derivation Functions) to use for the demo.
    KDFType kdf_type = parse_kdf_type(argc, argv);
    printf("Keys will be derived using: %s.\n",
           kdf_type == KDF_TYPE_KBKDF ? "KBKDF" : "HKDF");

    // Define several objects that will be initialized & used below. We define
    // them all at once, in the beginning, so we can use `goto` statements all
    // throughout this function to jump to the cleanup routine. 
    NCRYPT_PROV_HANDLE provider = NULL;          // <-- AziHSM provider handle
    NCRYPT_KEY_HANDLE p1_ecdh_key = NULL;        // <-- Alice's private ECDH key handle
    NCRYPT_KEY_HANDLE p2_ecdh_key = NULL;        // <-- Bob's private ECDH key handle
    BYTE* p1_ecdh_key_export = NULL;             // <-- Alice's exported ECDH public key data
    DWORD p1_ecdh_key_export_len = 0;            // <-- The length of Alice's public key data
    BYTE* p2_ecdh_key_export = NULL;             // <-- Bob's exported ECDH public key data
    DWORD p2_ecdh_key_export_len = 0;            // <-- The length of Bob's public key data
    NCRYPT_KEY_HANDLE p1_ecdh_public_key = NULL; // <-- Key handle for Alice's imported public key data
    NCRYPT_KEY_HANDLE p2_ecdh_public_key = NULL; // <-- Key handle for Bob's imported public key data
    NCRYPT_SECRET_HANDLE p1_secret = NULL;       // <-- Alice's shared secret handle.
    NCRYPT_SECRET_HANDLE p2_secret = NULL;       // <-- Bob's shared secret handle.
    NCRYPT_KEY_HANDLE p1_derived_key = NULL;     // <-- Alice's derived AES key.
    NCRYPT_KEY_HANDLE p2_derived_key = NULL;     // <-- Bob's derived AES key.
    const size_t plaintext_len = 128;            // <-- Length of shared plaintext.
    BYTE* plaintext = new BYTE[plaintext_len];   // <-- Shared plaintext when encrypting.
    const size_t iv_len = 16;                    // <-- Length of shared AES-CBC init vector.
    BYTE* iv = new BYTE[iv_len];                 // <-- Shared AES-CBC init vector when encrypting/decrypting.
    BYTE* iv_copy = new BYTE[iv_len];            // <-- Copy of the shared AES-CBC init vector.
    size_t p1_ciphertext_len = 0;                // <-- Alice's AES-encrypted ciphertext length.
    BYTE* p1_ciphertext = NULL;                  // <-- Alice's AES-encrypted ciphertext.
    size_t p2_decrypted_len = 0;                 // <-- Bob's AES-decrypted plaintext length.
    BYTE* p2_decrypted = NULL;                   // <-- Bob's AES-decrypted plaintext.
    char* hexstr = NULL;                         // <-- Pointer used for storing hexadecimal strings
    size_t hexstr_len = 0;                       // <-- Length field for `hexstr`
   
    // Start by opening a NCrypt provider handle to the AziHSM
    status = NCryptOpenStorageProvider(&provider, AZIHSM_KSP_NAME, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to open NCrypt Storage Provider handle. "
                "NCryptOpenStorageProvider returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    printf("Opened NCrypt Storage Provider handle: 0x%08x\n", (int) provider);


    // --------------- Step 1 - Generating Two ECDH Key Pairs --------------- //
    printf("\nStep 1: ECDH Key Pair Generate"
           "\n------------------------------\n");

    // The first step is to create two ECDH public/private key pairs; one for
    // each party.
    //
    // In this sample, we'll use ECC P256 as the keys' curve.

    // Generate the first ECDH key for "Alice" (the first party)
    status = create_ecdh_key(
        provider,
        BCRYPT_ECC_CURVE_NISTP256,
        &p1_ecdh_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Generated ECDH key for Alice: 0x%08x\n", (int) p1_ecdh_key);

    // Generate the second ECDH key for "Bob" (the second party)
    status = create_ecdh_key(
        provider,
        BCRYPT_ECC_CURVE_NISTP256,
        &p2_ecdh_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Generated ECDH key for Bob: 0x%08x\n", (int) p2_ecdh_key);

    
    // ---------- Step 2 - Exchanging Secrets with ECDH Key Pairs ----------- //
    printf("\nStep 2: ECDH Secret Exchange"
           "\n----------------------------\n");

    // Alice and Bob (our two parties) will start their public key exchange by
    // each invoking `NCryptExportKey()` to store the public key (in DER
    // format) in a buffer.

    // Export the first party's ("Alice") ECDH key
    status = export_ecdh_key(
        p1_ecdh_key,
        &p1_ecdh_key_export,
        &p1_ecdh_key_export_len
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Exported Alice's ECDH public key: %d bytes of data\n",
           p1_ecdh_key_export_len);

    // Export the second party's ("Bob") ECDH key
    status = export_ecdh_key(
        p2_ecdh_key,
        &p2_ecdh_key_export,
        &p2_ecdh_key_export_len
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Exported Bob's ECDH public key: %d bytes of data\n",
           p2_ecdh_key_export_len);

    // Next, to simulate the two parties importing each others' public keys
    // (the two buffers we just exported), we'll invoke `NCryptImportKey()`
    // twice below, once for each of the keys. These will give us a key handle
    // with which we can use Alice and Bob's public ECDH keys.
    
    // Import the first party's ("Alice") ECDH public key
    status = import_ecdh_key(
        provider,
        p1_ecdh_key_export,
        p1_ecdh_key_export_len,
        &p1_ecdh_public_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Imported Alice's ECDH public key: 0x%08x\n", (int) p1_ecdh_public_key);
    
    // Import the first party's ("Bob") ECDH public key
    status = import_ecdh_key(
        provider,
        p2_ecdh_key_export,
        p2_ecdh_key_export_len,
        &p2_ecdh_public_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Imported Bob's ECDH public key: 0x%08x\n", (int) p2_ecdh_public_key);

    // Lastly, with each party possessing their own private ECDH key *and*
    // their peer's imported public ECDH key, they'll securely generate a
    // shared secret (meaning, the secret value they each generate will be
    // identical). We'll simulate both parties doing this by calling
    // `NCryptSecretAgreement()` twice below.

    // Use Alice's private key, and Bob's imported public key, to generate a
    // shared secret for Alice.
    status = generate_secret(p1_ecdh_key, p2_ecdh_public_key, &p1_secret);
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Generated Alice's shared secret: 0x%08x\n", (int) p1_secret);
    
    // Use Bob's private key, and Alice's imported public key, to generate a
    // shared secret for Bob.
    status = generate_secret(p2_ecdh_key, p1_ecdh_public_key, &p2_secret);
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Generated Bob's shared secret: 0x%08x\n", (int) p2_secret);

    
    // ----------- Step 3 - Deriving AES Keys with KBKDF or HKDF ------------ //
    // This sample can demonstrate AES key derivation using either KBKDF
    // (Key-Based Key Derivation Function) or HKDF (HMAC-based Key Derivation
    // Function).

    if (kdf_type == KDF_TYPE_KBKDF)
    {
        printf("\nStep 3: KBKDF AES"
               "\n-----------------\n");
    }
    else // kdf_type == KDF_TYPE_HKDF
    {
        printf("\nStep 3: HKDF AES"
               "\n----------------\n");
    }

    // Next, the two parties will each derive an AES key from the shared secret
    // that was generated above.
    //
    // For this sample, we'll use SHA256 as the hashing algorithm, and we'll
    // choose between KBKDF and HKDF as our key derivation function.  The input
    // parameters for `NCryptDeriveKey()` differ between the two KDF types; see
    // the `derive_aes_key()` helper function for the details.
    //
    // We will derive an AES key with a length of 256 bits.

    // Use Alice's shared secret handle to have the AziHSM derive an AES key.
    status = derive_aes_key(
        provider,
        p1_secret,
        256,
        BCRYPT_SHA256_ALGORITHM,
        kdf_type,
        &p1_derived_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Derived Alice's AES key using %s: 0x%08x\n",
           kdf_type == KDF_TYPE_KBKDF ? "KBKDF" : "HKDF",
           (int) p1_derived_key);
    
    // Use Bob's shared secret handle to have the AziHSM derive an AES key.
    status = derive_aes_key(
        provider,
        p2_secret,
        256,
        BCRYPT_SHA256_ALGORITHM,
        kdf_type,
        &p2_derived_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Derived Bob's AES key using %s: 0x%08x\n",
           kdf_type == KDF_TYPE_KBKDF ? "KBKDF" : "HKDF",
           (int) p2_derived_key);
    
   
    // ------------ Step 4 - Performing AES-CBC Encrypt/Decrypt ------------- //
    printf("\nStep 4: AES-CBC Encrypt/Decrypt"
           "\n-------------------------------\n");

    // At this point, we have successfully derived two AES keys; one for each
    // party ("Alice" and "Bob). We will now encrypt plaintext with Alice's
    // key, and decrypt the ciphertext with Bob's key, to confirm that the
    // resulting decrypted plaintext matches the original plaintext.
    //
    // Showing this proves that this method can be used to establish a secure
    // communication channel between two parties.

    // Fill the plaintext and initialization vector buffers with random values.
    status = HRESULT_FROM_NT(randomize_buffer(plaintext, plaintext_len));
    if (FAILED(status))
    {
        goto cleanup;
    }
    status = HRESULT_FROM_NT(randomize_buffer(iv, iv_len));
    if (FAILED(status))
    {
        goto cleanup;
    }

    // Make a copy of the init vector. We'll use this identical copy as the
    // input to `NCryptDecrypt()`, to ensure both parties (Alice, who is
    // encrypting, and Bob, who is decrypting) use the exact same init vector.
    memcpy(iv_copy, iv, sizeof(BYTE) * iv_len);
    
    // Display the plaintext as a hex string:
    if (FAILED(buffer_to_hex(plaintext, plaintext_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("Plaintext to be encrypted: [%s]\n", hexstr);
    free(hexstr);
    
    // Display the initialization vector as a hex string:
    if (FAILED(buffer_to_hex(iv, iv_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("AES-CBC Initialization Vector: [%s]\n", hexstr);
    free(hexstr);
    
    // Encrypt the plaintext as the first party ("Alice"), using her derived
    // AES key.
    status = encrypt_aes_cbc(
        p1_derived_key,
        plaintext,
        plaintext_len,
        iv,
        iv_len,
        &p1_ciphertext,
        &p1_ciphertext_len
    );
    
    // Display Alice's ciphertext
    if (FAILED(buffer_to_hex(p1_ciphertext, p1_ciphertext_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("Encrypted plaintext with Alice's AES key: [%s]\n", hexstr);
    free(hexstr);

    // Decrypt the ciphertext as the second party ("Bob"), using his derived
    // AES key.
    status = decrypt_aes_cbc(
        p2_derived_key,
        p1_ciphertext,
        p1_ciphertext_len,
        iv_copy,
        iv_len,
        &p2_decrypted,
        &p2_decrypted_len
    );

    // Display Bob's plaintext:
    if (FAILED(buffer_to_hex(p2_decrypted, p2_decrypted_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("Decrypted ciphertext with Bob's AES key: [%s]\n", hexstr);
    free(hexstr);

    // Compare the decrypted ciphertext's length with the original plaintext's
    // length. These should be identical.
    if (plaintext_len != p2_decrypted_len)
    {
        fprintf(stderr, "The decrypted ciphertext's length (%zu) does not match the original plaintext's length (%zu).\n",
                p2_decrypted_len,
                plaintext_len);
        status = E_FAIL;
        goto cleanup;
    }

    // Next, compare each byte in the decrypted ciphertext with the
    // corresponding byte in the original plaintext. These should all be
    // identical.
    for (size_t i = 0; i < plaintext_len; i++)
    {
        // If any two bytes mismatch, then something has gone wrong:
        if (plaintext[i] != p2_decrypted[i])
        {
            fprintf(stderr, "The decrypted ciphertext does not match the original plaintext.\n");
            status = E_FAIL;
            goto cleanup;
        }
    }
    printf("The decrypted ciphertext matches the original plaintext!\n");

    // After successfully verifying that Bob's decrypted ciphertext matches the
    // original plaintext (which was encrypted by Alice), the demo is a
    // success! We have successfully shown that the AziHSM can be used in this
    // scenario to exchange a shared secret and use it to set up a secure line
    // of communication between two parties.

    
    // -------------------------- Cleanup Routine --------------------------- //
    // Label for cleaning up resources after encountering an error or ending
    // the demo. Frees the NCrypt provider handle and any other live resources.
    status = S_OK;
cleanup:
    // Preserve the exit status from wherever we just came from, so the process
    // can exit with it. This lets us be sure that if the process exists with
    // `S_OK`, we know that all steps in the demo succeeded.
    HRESULT exit_status = status;

    printf("\nCleaning Up"
           "\n-----------\n");
    
    // Free encrypted/decrypted ciphertext/plaintext buffers:
    if (p2_decrypted != NULL)
    {
        delete[] p2_decrypted;
        p2_decrypted = NULL;
        printf("Freed Bob's decrypted ciphertext buffer.\n");
    }
    if (p1_ciphertext != NULL)
    {
        delete[] p1_ciphertext;
        p1_ciphertext = NULL;
        printf("Freed Alice's encrypted plaintext buffer.\n");
    }

    // Free plaintext and initialization vector buffers
    if (iv_copy != NULL)
    {
        delete[] iv_copy;
        iv_copy = NULL;
        printf("Freed AES initialization vector copy.\n");
    }
    if (iv != NULL)
    {
        delete[] iv;
        iv = NULL;
        printf("Freed AES initialization vector.\n");
    }
    if (plaintext != NULL)
    {
        delete[] plaintext;
        plaintext = NULL;
        printf("Freed plaintext buffer.\n");
    }

    // Is Bob's derived AES key in use? Free it
    if (p2_derived_key != NULL)
    {
        status = NCryptFreeObject(p2_derived_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Bob's derived AES key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p2_derived_key = NULL;
            printf("Freed Bob's derved AES key handle.\n");
        }
    }

    // Is Alice's derived AES key in use? Free it
    if (p1_derived_key != NULL)
    {
        status = NCryptFreeObject(p1_derived_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Alice's derived AES key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p1_derived_key = NULL;
            printf("Freed Alice's derved AES key handle.\n");
        }
    }

    // Is Bob's shared secret in use? Free it
    if (p2_secret != NULL)
    {
        status = NCryptFreeObject(p2_secret);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Bob's shared secret handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p2_secret = NULL;
            printf("Freed Bob's shared secret handle.\n");
        }
    }

    // Is Alice's shared secret in use? Free it
    if (p1_secret != NULL)
    {
        status = NCryptFreeObject(p1_secret);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Alice's shared secret handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p1_secret = NULL;
            printf("Freed Alice's shared secret handle.\n");
        }
    }

    // Is Bob's imported ECDH public key still in use? Free it
    if (p2_ecdh_public_key != NULL)
    {
        status = NCryptFreeObject(p2_ecdh_public_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Bob's imported ECDH public key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p2_ecdh_public_key = NULL;
            printf("Freed Bob's imported ECDH public key handle.\n");
        }
    }

    // Is Alice's imported ECDH public key still in use? Free it
    if (p1_ecdh_public_key != NULL)
    {
        status = NCryptFreeObject(p1_ecdh_public_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Alice's imported ECDH public key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p1_ecdh_public_key = NULL;
            printf("Freed Alice's imported ECDH public key handle.\n");
        }
    }

    // If the two exported ECDH key buffers have not been freed, do so now.
    if (p2_ecdh_key_export != NULL)
    {
        delete[] p2_ecdh_key_export;
        p2_ecdh_key_export = NULL;
        printf("Freed Bob's exported ECDH public key data buffer.\n");
    }
    if (p1_ecdh_key_export != NULL)
    {
        delete[] p1_ecdh_key_export;
        p1_ecdh_key_export = NULL;
        printf("Freed Alice's exported ECDH public key data buffer.\n");
    }

    // Is Bob's ECDH key handle still in use at this point? If so, free it.
    if (p2_ecdh_key != NULL)
    {
        status = NCryptFreeObject(p2_ecdh_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Bob's ECDH key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p2_ecdh_key = NULL;
            printf("Freed Bob's ECDH key handle.\n");
        }
    }

    // Is Alice's ECDH key handle still in use at this point? If so, free it.
    if (p1_ecdh_key != NULL)
    {
        status = NCryptFreeObject(p1_ecdh_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free Alice's ECDH key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            p1_ecdh_key = NULL;
            printf("Freed Alice's ECDH key handle.\n");
        }
    }

    // Close the handle to the NCrypt provider, if it is initialized
    if (provider != NULL)
    {
        status = NCryptFreeObject(provider);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free NCrypt Storage Provider handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            provider = NULL;
            printf("Freed NCrypt Storage Provider handle.\n");
        }
    }

    if (SUCCEEDED(exit_status))
    {
        printf("Demo succeeded!\n");
    }

    return (int) exit_status;
}

