// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check readme.md for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Import an RSA key into the AziHSM by wrapping it into an encrypted blob.
// 2. Use the imported RSA key to encrypt data.
// 3. Use the imported RSA key to decrypt data.
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

// Use `WIN32_NO_STATUS` to prevent macro-redefinition warnings in `ntstatus.h`
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>
#include <ncrypt.h>

#include <cstdio>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"
#include "Utils/RsaWrapUtils.h"

#include "RsaKeys.h"

// Force the linking of the NCrypt library into this executable, so we can
// access NCrypt symbols in our code below:
#pragma comment(lib, "ncrypt.lib")

// Helper enum used to differentiate between the three supported RSA key
// lengths.
typedef enum _RsaKeyLength
{
    RSA_KEY_LENGTH_2048,
    RSA_KEY_LENGTH_3072,
    RSA_KEY_LENGTH_4096
} RsaKeyLength;

// Helper function that returns a pointer to the buffer containing the private
// RSA key of the specified length.
static BYTE* get_rsa_private_key_data_ptr(RsaKeyLength keylen)
{
    switch (keylen)
    {
        case RSA_KEY_LENGTH_2048:
            return (BYTE*) RSA_2K_PRIVATE_KEY;
        case RSA_KEY_LENGTH_3072:
            return (BYTE*) RSA_3K_PRIVATE_KEY;
        case RSA_KEY_LENGTH_4096:
            return (BYTE*) RSA_4K_PRIVATE_KEY;
        default:
            return NULL;
    }
}

// Helper function that returns the length of the buffer containing the private
// RSA key of the specified length.
static DWORD get_rsa_private_key_data_len(RsaKeyLength keylen)
{
    switch (keylen)
    {
        case RSA_KEY_LENGTH_2048:
            return RSA_2K_PRIVATE_KEY_LEN;
        case RSA_KEY_LENGTH_3072:
            return RSA_3K_PRIVATE_KEY_LEN;
        case RSA_KEY_LENGTH_4096:
            return RSA_4K_PRIVATE_KEY_LEN;
        default:
            return 0;
    }
}

// Helper function that opens a handle to the AziHSM's built-in unwrap key.
static SECURITY_STATUS open_unwrap_key(NCRYPT_PROV_HANDLE provider,
                                       NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;
    NCRYPT_KEY_HANDLE unwrap_key = NULL;

    // Start by opening a handle to Manticore's built-in unwrapping key.
    status = NCryptOpenKey(
        provider,
        &unwrap_key,
        AZIHSM_BUILTIN_UNWRAP_KEY_NAME,
        0,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to open the built-in unwrap key. "
                "NCryptOpenKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // Set return pointer and a successful status code
    *result = unwrap_key;
    unwrap_key = NULL;
    status = S_OK;
cleanup:
    SECURITY_STATUS exit_status = status;
    return exit_status;
}

// Helper function that accepts a pointer to a buffer containing raw RSA key
// data (representing the key to be imported into AziHSM) and wraps it with
// AziHSM's built-in unwrapping key.
//
// The resulting key blob is returned by updating `*result` and `*result_len`
// to point at the resulting buffer and its length.
//
// The `keylen` parameter is used to determine which RSA key length (2k, 3k,
// 4k) to use when constructing a wrapped key blob.
//
// The `hash_alg` parameter is used to specify what hashing algorithm to use
// when generating the wrapped key blob.
static SECURITY_STATUS wrap_rsa_key(NCRYPT_PROV_HANDLE provider,
                                    NCRYPT_KEY_HANDLE unwrap_key,
                                    RsaKeyLength keylen,
                                    LPCWSTR hash_alg,
                                    BYTE** result,
                                    DWORD* result_len)
{
    SECURITY_STATUS status = S_OK;
    
    BYTE* rsa_private_key_data = NULL;
    DWORD rsa_private_key_data_len = 0;
    DWORD unwrap_key_data_len_max = 600;
    DWORD unwrap_key_data_len = 0;
    BYTE* unwrap_key_data = NULL;
    DWORD blob_data_len = 0;
    BYTE* blob_data = NULL;

    // --------------------- Built-In Unwrap Key Export --------------------- //
    // Allocate a buffer to store the public RSA key, which we'll extract
    // below via `NCryptExportKey()`.
    unwrap_key_data = new BYTE[unwrap_key_data_len_max];

    // Next, export the public key's contents (which we get from the
    // built-in unwrapping key) to an array.
    status = NCryptExportKey(
        unwrap_key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        unwrap_key_data,
        unwrap_key_data_len_max,
        &unwrap_key_data_len,
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to export the built-in unwrap key. "
                "NCryptExportKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // ---------------------- Wrapped Blob Generation ----------------------- //
    // The next step is to use the built-in unwrap key's data (and an AES key
    // that we will randomly generate) to create a key blob. This is the blob
    // that will allow us to import the external RSA key into the AziHSM.
    //
    // All of this is taken care of by the `ExportKeyWrapped()` helper function
    // invoked below. See its definition for more information on this process.

    // Retrieve the RSA private key we want to import.
    rsa_private_key_data = get_rsa_private_key_data_ptr(keylen);
    rsa_private_key_data_len = get_rsa_private_key_data_len(keylen);
    if (rsa_private_key_data == NULL)
    {
        fprintf(stderr, "Unexpected RSA key length specified: %d.\n",
                (int) keylen);
        goto cleanup;
    }

    status = HRESULT_FROM_NT(ExportKeyWrapped(
        (PBYTE) rsa_private_key_data,
        rsa_private_key_data_len,
        (PBYTE) unwrap_key_data,
        (DWORD) unwrap_key_data_len,
        hash_alg,
        &blob_data,
        &blob_data_len
    ));
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to generate wrapped RSA key blob."
                "ExportKeyWrapped returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Key blob successfully generated. Set return pointers and a successful
    // status message.
    *result = blob_data;
    *result_len = blob_data_len;
    blob_data = NULL;
    blob_data_len = 0;
    status = S_OK;
cleanup:
    SECURITY_STATUS exit_status = status;

    // Free the exported unwrap key data buffer, if it was allocated.
    if (unwrap_key_data != NULL)
    {
        delete[] unwrap_key_data;
    }

    return exit_status;
}

// Helper function that imports the provided key blob into AziHSM using the
// NCrypt API.
//
// On success, `*result` is updated to store the handle of the imported key.
static SECURITY_STATUS import_key_blob(NCRYPT_PROV_HANDLE provider,
                                       NCRYPT_KEY_HANDLE unwrap_key,
                                       BYTE* blob_data,
                                       DWORD blob_data_len,
                                       DWORD key_usage_flag,
                                       NCRYPT_KEY_HANDLE* result)
{
    SECURITY_STATUS status = S_OK;
    NCRYPT_KEY_HANDLE key = 0;

    // Create an `NCryptBuffer` object to contain the algorithm ID string.
    const DWORD param_buffers_len = 1;
    NCryptBuffer param_buffers[param_buffers_len];
    param_buffers[0].cbBuffer = static_cast<ULONG>(wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR);
    param_buffers[0].BufferType = NCRYPTBUFFER_PKCS_ALG_ID;
    param_buffers[0].pvBuffer = (PVOID) BCRYPT_RSA_ALGORITHM;
    
    // Pack the buffer into an `NCryptBufferDesc` object, which we'll pass
    // into `NCryptImportKey`.
    NCryptBufferDesc params;
    params.ulVersion = NCRYPTBUFFER_VERSION;
    params.cBuffers = param_buffers_len;
    params.pBuffers = param_buffers;

    // Invoke `NCryptImportKey` to import the key blob.
    // We specify `NCRYPT_DO_NOT_FINALIZE_FLAG` here, because we will be
    // setting key properties after importing, and before finalizing.
    status = NCryptImportKey(
        provider,
        unwrap_key,
        BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
        &params,
        &key,
        (PBYTE) blob_data,
        (DWORD) blob_data_len,
        NCRYPT_DO_NOT_FINALIZE_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to import wrapped key blob. "
                "NCryptImportKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    // Set the key's usage with the provided flag.
    status = NCryptSetProperty(
        key,
        NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE) &key_usage_flag,
        sizeof(DWORD),
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to set imported RSA key usage property. "
                "NCryptSetProperty returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Optionally, you can set a custom key property supported by the AziHSM
    // that can enable or disable RSA-CRT (Chinese Remainder Theorem) for the
    // imported key.
    //
    // CRT is an optimization of the RSA algorithm that yields faster crypto
    // operations, but comes at the cost of requiring more space to store the
    // RSA key.
    //
    // By default, RSA keys imported into AziHSM are imported with RSA enabled.
    // This property can be set to disable it, if you wish.
    //
    // For the sake of demonstration, we will set this property to explicitly
    // *enable* CRT.
    status = NCryptSetProperty(
        key,
        AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_NAME,
        (PBYTE) &AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED,
        sizeof(DWORD),
        0
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to set imported RSA CRT-enabled property. "
                "NCryptSetProperty returned: 0x%08x\n",
                status);
        goto cleanup;
    }

    // Finalize the key, now that we've finished setting key properties.
    status = NCryptFinalizeKey(key, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to import wrapped key blob. "
                "NCryptImportKey returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    
    *result = key;
    key = NULL;
    status = S_OK;
cleanup:
    SECURITY_STATUS exit_status = status;
    
    // If the key handle was never transferred to the return parameter,
    // something went wrong; free it here
    if (key != NULL)
    {
        status = NCryptFreeObject(key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free imported key handle after error. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            key = NULL;
        }
    }

    return exit_status;
}

// Helper function that encrypts the provided plaintext using the provided key
// handle. The resulting ciphertext is allocated into a new buffer, and
// `*result` is updated to point at it.
static SECURITY_STATUS encrypt(NCRYPT_KEY_HANDLE key,
                               BYTE* plaintext,
                               size_t plaintext_len,
                               wchar_t* oaep_label,
                               size_t oaep_label_len,
                               LPCWSTR oaep_alg,
                               BYTE** result,
                               size_t* result_len)
{
    SECURITY_STATUS status = S_OK;
    BYTE* ciphertext = NULL;
    size_t ciphertext_len = 0;

    // Create a struct for using OAEP padding for encryption.
    // The following options for algorithm IDs are available:
    //
    // * `NCRYPT_SHA256_ALGORITHM`
    // * `NCRYPT_SHA384_ALGORITHM`
    // * `NCRYPT_SHA512_ALGORITHM`
    BCRYPT_OAEP_PADDING_INFO pinfo;
    pinfo.pszAlgId = oaep_alg;
    pinfo.pbLabel = (PUCHAR) oaep_label;
    pinfo.cbLabel = (ULONG) oaep_label_len;

    // Call `NCryptEncrypt` once, to determine how many bytes are needed to
    // store the ciphertext.
    status = NCryptEncrypt(
        key,
        (PBYTE) plaintext,
        (DWORD) plaintext_len,
        &pinfo,
        NULL,
        0,
        (DWORD*) &ciphertext_len,
        NCRYPT_PAD_OAEP_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to encrypt plaintext. "
                "NCryptEncrypt (call #1) returned: 0x%08x.\n",
                status);
        goto cleanup;
    }
    
    // Allocate a buffer to store the ciphertext, then call `NCryptEncrypt` a
    // second time to generate it and store the result.
    ciphertext = new BYTE[ciphertext_len];
    status = NCryptEncrypt(
        key,
        (PBYTE) plaintext,
        (DWORD) plaintext_len,
        &pinfo,
        ciphertext,
        (DWORD) ciphertext_len,
        (DWORD*) &ciphertext_len,
        NCRYPT_PAD_OAEP_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to encrypt plaintext. "
                "NCryptEncrypt (call #2) returned: 0x%08x.\n",
                status);
        goto cleanup;
    }
    
    // Set return pointers and a success exit status
    *result = ciphertext;
    *result_len = ciphertext_len;
    ciphertext = NULL;
    ciphertext_len = 0;
    status = S_OK;
cleanup:
    SECURITY_STATUS exit_status = status;

    // Free the ciphertext buffer if it was not properly transferred to
    // `*result` (indicating that something went wrong)
    if (ciphertext != NULL)
    {
        delete[] ciphertext;
        ciphertext = NULL;
        ciphertext_len = 0;
    }

    return exit_status;
}

// Helper function that decrypts the provided ciphertext using the provided key
// handle. The resulting plaintext is allocated into a new buffer, and
// `*result` is updated to point at it.
static SECURITY_STATUS decrypt(NCRYPT_KEY_HANDLE key,
                               BYTE* ciphertext,
                               size_t ciphertext_len,
                               wchar_t* oaep_label,
                               size_t oaep_label_len,
                               LPCWSTR oaep_alg,
                               BYTE** result,
                               size_t* result_len)
{
    SECURITY_STATUS status = S_OK;
    BYTE* decrypted = NULL;
    size_t decrypted_len = 0;

    // Create a struct for using OAEP padding for decryption.
    // The following options for algorithm IDs are available:
    //
    // * `NCRYPT_SHA256_ALGORITHM`
    // * `NCRYPT_SHA384_ALGORITHM`
    // * `NCRYPT_SHA512_ALGORITHM`
    BCRYPT_OAEP_PADDING_INFO pinfo;
    pinfo.pszAlgId = oaep_alg;
    pinfo.pbLabel = (PUCHAR) oaep_label;
    pinfo.cbLabel = (ULONG) oaep_label_len;

    // Call `NCryptDecrypt` once, to determine how many bytes are needed to
    // store the plaintext.
    status = NCryptDecrypt(
        key,
        (PBYTE) ciphertext,
        (DWORD) ciphertext_len,
        &pinfo,
        NULL,
        0,
        (DWORD*) &decrypted_len,
        NCRYPT_PAD_OAEP_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to decrypt ciphertext. "
                "NCryptDecrypt (call #2) returned: 0x%08x.\n",
                status);
        goto cleanup;
    }
    
    // Allocate a buffer to store the plaintext, then call `NCryptDecrypt` a
    // second time to generate it and store the result.
    decrypted = new BYTE[decrypted_len];
    status = NCryptDecrypt(
        key,
        (PBYTE) ciphertext,
        (DWORD) ciphertext_len,
        &pinfo,
        decrypted,
        (DWORD) decrypted_len,
        (DWORD*) &decrypted_len,
        NCRYPT_PAD_OAEP_FLAG
    );
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to decrypt plaintext. "
                "NCryptDecrypt (call #2) returned: 0x%08x.\n",
                status);
        goto cleanup;
    }
    
    // Set return pointers and a success exit status
    *result = decrypted;
    *result_len = decrypted_len;
    decrypted = NULL;
    decrypted_len = 0;
    status = S_OK;
cleanup:
    SECURITY_STATUS exit_status = status;

    // Free the plaintext buffer if it was not properly transferred to
    // `*result` (indicating that something went wrong)
    if (decrypted != NULL)
    {
        delete[] decrypted;
        decrypted = NULL;
        decrypted_len = 0;
    }

    return exit_status;
}

// Helper function that searches the command-line arguments provided by the
// user for an RSA key length specification.
static RsaKeyLength parse_key_len(int argc, char** argv)
{
    RsaKeyLength result = RSA_KEY_LENGTH_2048;

    // Iterate through each command-line argument (skipping the first, which is
    // the executable path) and look for key lengths. Convert strings to
    // lowercase to allow for case insensitive matches.
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

        if (!strcmp(str, "2048") || !strcmp(str, "2k"))
        {
            result = RSA_KEY_LENGTH_2048;
        }
        else if (!strcmp(str, "3072") || !strcmp(str, "3k"))
        {
            result = RSA_KEY_LENGTH_3072;
        }
        else if (!strcmp(str, "4096") || !strcmp(str, "4k"))
        {
            result = RSA_KEY_LENGTH_4096;
        }

        delete[] str;
    }
    
    return result;
}

int main(int argc, char** argv)
{
    printf("AziHSM Demonstration: RSA Key Import --> RSA Encrypt --> RSA Decrypt\n");
    printf("====================================================================\n");

    HRESULT status = S_OK;

    // Parse the RSA key length from the command-line
    RsaKeyLength keylen = parse_key_len(argc, argv);
    switch (keylen)
    {
        case RSA_KEY_LENGTH_2048:
            printf("The imported RSA key will have a length of 2048.\n");
            break;
        case RSA_KEY_LENGTH_3072:
            printf("The imported RSA key will have a length of 3072.\n");
            break;
        case RSA_KEY_LENGTH_4096:
            printf("The imported RSA key will have a length of 4096.\n");
            break;
        default:
            fprintf(stderr, "Unexpected RSA key length provided.\n");
            return E_FAIL;
    }
    
    // Define several variables used throughout the main function.
    NCRYPT_PROV_HANDLE provider = NULL;                 // <-- AziHSM KSP handle
    NCRYPT_KEY_HANDLE unwrap_key = NULL;                // <-- Built-in unwrap key handle
    LPCWSTR hash_alg = NCRYPT_SHA256_ALGORITHM;         // <-- Hashing algorithm to use for key blob
    BYTE* blob_data = NULL;                             // <-- Wrapped key blob data pointer
    DWORD blob_data_len = 0;                            // <-- Wrapped key blob data length
    DWORD key_usage_flag = NCRYPT_ALLOW_DECRYPT_FLAG;   // <-- Usage flag for the imported RSA key
    NCRYPT_KEY_HANDLE imported_key = NULL;              // <-- Imported RSA key handle
    BYTE* plaintext = NULL;                             // <-- Buffer of plaintext to encrypt.
    size_t plaintext_len = 0;                           // <-- Number of bytes of plaintext to encrypt.
    BYTE* ciphertext = NULL;                            // <-- Buffer of ciphertext to decrypt.
    size_t ciphertext_len = 0;                          // <-- Number of bytes of ciphertext to decrypt.
    BYTE* decrypted = NULL;                             // <-- Buffer of containing decrypted ciphertext.
    size_t decrypted_len = 0;                           // <-- Number of bytes of decrypted ciphertext.
    char* hexstr = NULL;                                // <-- Pointer used for storing hexadecimal strings
    size_t hexstr_len = 0;                              // <-- Length field for `hexstr`
    const wchar_t* oaep_label = L"labeldata";           // <-- Data used for OAEP padding for RSA encrypt/decrypt
    const size_t oaep_label_len = wcslen(oaep_label);   // Length of the OAEP padding label string
    LPCWSTR oaep_alg = NCRYPT_SHA256_ALGORITHM;         // <-- Hashing algorithm to use for OAEP padding
    
    // Open a handle to the AziHSM via the NCrypt API.
    status = NCryptOpenStorageProvider(&provider, AZIHSM_KSP_NAME, 0);
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to open NCrypt Storage Provider handle. "
                "NCryptOpenStorageProvider returned: 0x%08x\n",
                status);
        goto cleanup;
    }
    printf("Opened NCrypt Storage Provider handle: 0x%08x\n", (int) provider);

    
    // -------------------- Step 1 - Import the RSA Key --------------------- //
    printf("\nStep 1: Import RSA Key"
           "\n----------------------\n");

    // Open a handle to the built-in unwrap key
    status = open_unwrap_key(provider, &unwrap_key);
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Opened handle to built-in unwrap key: 0x%08x.\n", (int) unwrap_key);

    // Invoke the helper function that will generate the key blob and point
    // `blob_data` to the resulting buffer.
    //
    // The `hash_alg` specifies what hashing algorithm to use when generating
    // the blob. This sample uses SHA256 (`NCRYPT_SHA256_ALGORITHM`), but the
    // following options are also available:
    //
    // * `NCRYPT_SHA1_ALGORITHM`
    // * `NCRYPT_SHA256_ALGORITHM`
    // * `NCRYPT_SHA384_ALGORITHM`
    // * `NCRYPT_SHA512_ALGORITHM`
    status = wrap_rsa_key(
        provider,
        unwrap_key,
        keylen,
        hash_alg,
        &blob_data,
        &blob_data_len
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Created wrapped RSA key blob: %d bytes of data.\n",
           blob_data_len);
    
    // Next, take the blob and import into the AziHSM as an RSA key.
    status = import_key_blob(
        provider,
        unwrap_key,
        blob_data,
        blob_data_len,
        key_usage_flag,
        &imported_key
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Successfully imported key into AziHSM. Got handle: 0x%08x.\n",
           (int) imported_key);

    
    // --------------- Step 2 - Generate & Encrypt Plaintext ---------------- //
    printf("\nStep 2: Encrypt Plaintext"
           "\n-------------------------\n");

    // Allocate a buffer of plaintext to encrypt, and fill it with random
    // bytes.
    plaintext_len = 128;
    plaintext = new BYTE[plaintext_len];
    status = HRESULT_FROM_NT(randomize_buffer(plaintext, plaintext_len));
    if (FAILED(status))
    {
        fprintf(stderr, "Failed to generate a random buffer of plaintext. "
                "Helper function returned: 0x%08x.\n",
                status);
        goto cleanup;
    }

    // Display the plaintext as a hex string:
    if (FAILED(buffer_to_hex(plaintext, plaintext_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("Plaintext to be encrypted: [%s]\n", hexstr);
    free(hexstr);

    // Next, invoke the helper function to encrypt the plaintext, using the RSA
    // key we just imported.
    status = encrypt(
        imported_key,
        plaintext,
        plaintext_len,
        (wchar_t*) oaep_label,
        (size_t) oaep_label_len,
        oaep_alg,
        &ciphertext,
        &ciphertext_len
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Successfully encrypted plaintext: %zu bytes of ciphertext.\n",
           ciphertext_len);

    // Display the ciphertext as a hex string:
    if (FAILED(buffer_to_hex(ciphertext, ciphertext_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("Ciphertext: [%s]\n", hexstr);
    free(hexstr);
    
    
    // ------------------ Step 3 - Decrypt the Ciphertext ------------------- //
    printf("\nStep 3: Decrypt Ciphertext"
           "\n--------------------------\n");

    // Invoke the helper function to decrypt the plaintext, using the RSA key
    // we just imported.
    status = decrypt(
        imported_key,
        ciphertext,
        ciphertext_len,
        (wchar_t*) oaep_label,
        (size_t) oaep_label_len,
        oaep_alg,
        &decrypted,
        &decrypted_len
    );
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf("Successfully decrypted ciphertext: %zu bytes of plaintext.\n",
           decrypted_len);

    // Display the ciphertext as a hex string:
    if (FAILED(buffer_to_hex(decrypted, decrypted_len, &hexstr, &hexstr_len)))
    {
        goto cleanup;
    }
    printf("Decrypted plaintext: [%s]\n", hexstr);
    free(hexstr);

    // Compare the decrypted ciphertext's length with the original plaintext's
    // length. These should be identical.
    if (plaintext_len != decrypted_len)
    {
        fprintf(stderr, "The decrypted ciphertext's length (%zu) does not match the original plaintext's length (%zu).\n",
                decrypted_len,
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
        if (plaintext[i] != decrypted[i])
        {
            fprintf(stderr, "The decrypted ciphertext does not match the original plaintext.\n");
            status = E_FAIL;
            goto cleanup;
        }
    }
    printf("The decrypted ciphertext matches the original plaintext!\n");

    status = S_OK;
cleanup:
    // Preserve the exit status from wherever we just came from, so the process
    // can exit with it.
    HRESULT exit_status = status;

    printf("\nCleaning Up"
           "\n-----------\n");

    // Free the decrypted ciphertext buffer
    if (decrypted != NULL)
    {
        delete[] decrypted;
        decrypted = NULL;
        decrypted_len = 0;
        printf("Freed decrypted ciphertext buffer.\n");
    }
    
    // Free the ciphertext buffer
    if (ciphertext != NULL)
    {
        delete[] ciphertext;
        ciphertext = NULL;
        ciphertext_len = 0;
        printf("Freed ciphertext buffer.\n");
    }
    
    // Free the plaintext buffer
    if (plaintext != NULL)
    {
        delete[] plaintext;
        plaintext = NULL;
        plaintext_len = 0;
        printf("Freed plaintext buffer.\n");
    }
    
    // Free the handle to the imported RSA key
    if (imported_key != NULL)
    {
        status = NCryptFreeObject(imported_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free imported key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            printf("Freed imported key handle.\n");
            imported_key = NULL;
        }
    }

    // Free the wrapped key blob data, if it is allocated
    if (blob_data != NULL)
    {
        delete[] blob_data;
        blob_data = NULL;
        blob_data_len = 0;
        printf("Freed wrapped key blob data.\n");
    }

    // Free the handle to the AziHSM built-in unwrapping key
    if (unwrap_key != NULL)
    {
        status = NCryptFreeObject(unwrap_key);
        if (FAILED(status))
        {
            fprintf(stderr, "Failed to free built-in unwrap key handle. "
                    "NCryptFreeObject returned: 0x%08x\n",
                    status);
        }
        else
        {
            printf("Freed built-in unwrap key handle.\n");
            unwrap_key = NULL;
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
            printf("Freed NCrypt Storage Provider handle.\n");
            provider = NULL;
        }
    }

    if (SUCCEEDED(exit_status))
    {
        printf("Demo succeeded!\n");
    }

    return (int) exit_status;
}
