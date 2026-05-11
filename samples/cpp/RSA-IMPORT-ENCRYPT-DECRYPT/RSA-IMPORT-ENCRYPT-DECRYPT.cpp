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

#include <iostream>
#include <cstdio>
#include <string>
#include <algorithm>

#include <windows.h>
#include <ncrypt.h>

#include <wil/resource.h>
#include <wil/result.h>

#include "AziHSM/AziHSM.h"
#include "Utils/RsaWrapUtils.h"
#include "Utils/CryptoUtils.h"

#include "RsaKeys.h"

// Helper enum used to differentiate between the three supported RSA key
// lengths.
enum class RsaKeyLength
{
    RSA_KEY_LENGTH_2048,
    RSA_KEY_LENGTH_3072,
    RSA_KEY_LENGTH_4096
};

// Helper function that returns a pointer to the buffer containing the private
// RSA key of the specified length.
_Ret_maybenull_ BYTE *get_rsa_private_key_data_ptr(_In_ RsaKeyLength keylen)
{
    switch (keylen)
    {
    case RsaKeyLength::RSA_KEY_LENGTH_2048:
        return (BYTE *)RSA_2K_PRIVATE_KEY;
    case RsaKeyLength::RSA_KEY_LENGTH_3072:
        return (BYTE *)RSA_3K_PRIVATE_KEY;
    case RsaKeyLength::RSA_KEY_LENGTH_4096:
        return (BYTE *)RSA_4K_PRIVATE_KEY;
    default:
        return nullptr;
    }
}

// Helper function that returns the length of the buffer containing the private
// RSA key of the specified length.
DWORD get_rsa_private_key_data_len(_In_ RsaKeyLength keylen)
{
    switch (keylen)
    {
    case RsaKeyLength::RSA_KEY_LENGTH_2048:
        return RSA_2K_PRIVATE_KEY_LEN;
    case RsaKeyLength::RSA_KEY_LENGTH_3072:
        return RSA_3K_PRIVATE_KEY_LEN;
    case RsaKeyLength::RSA_KEY_LENGTH_4096:
        return RSA_4K_PRIVATE_KEY_LEN;
    default:
        return 0;
    }
}

// Helper function that accepts a pointer to a buffer containing raw RSA key
// data (representing the key to be imported into AziHSM) and wraps it with
// AziHSM's built-in unwrapping key.
//
// The `keylen` parameter is used to determine which RSA key length (2k, 3k,
// 4k) to use when constructing a wrapped key blob.
//
// The `hash_alg` parameter is used to specify what hashing algorithm to use
// when generating the wrapped key blob.
HRESULT wrap_rsa_key(_In_ const NCRYPT_PROV_HANDLE &provider,
                     _In_ const NCRYPT_KEY_HANDLE &unwrap_key,
                     _In_ const RsaKeyLength keylen,
                     _In_ LPCWSTR hash_alg,
                     _Out_ std::vector<BYTE> &outBlob)
{
    UNREFERENCED_PARAMETER(provider);
    RETURN_HR_IF_MSG(E_INVALIDARG, unwrap_key == 0, "Invalid unwrap key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, hash_alg == nullptr || *hash_alg == L'\0', "Hash algorithm must not be empty");

    // --------------------- Built-In Unwrap Key Export --------------------- //
    // Allocate a buffer to store the public RSA key, which we'll extract
    // below via `NCryptExportKey()`.
    std::vector<BYTE> unwrap_key_data(1024);

    // Next, export the public key's contents (which we get from the
    // built-in unwrapping key) to an array.
    DWORD bytes;
    RETURN_IF_FAILED_MSG(NCryptExportKey(
                             unwrap_key,
                             NULL,
                             BCRYPT_RSAPUBLIC_BLOB,
                             NULL,
                             unwrap_key_data.data(),
                             (DWORD)unwrap_key_data.size(),
                             &bytes,
                             0),
                         "Failed NCryptExportKey");
    RETURN_HR_IF_MSG(E_UNEXPECTED, bytes == 0 || bytes > unwrap_key_data.size(), "Unexpected unwrap public key length: %u", bytes);
    unwrap_key_data.resize(bytes);

    // ---------------------- Wrapped Blob Generation ----------------------- //
    // The next step is to use the built-in unwrap key's data (and an AES key
    // that we will randomly generate) to create a key blob. This is the blob
    // that will allow us to import the external RSA key into the AziHSM.
    //
    // All of this is taken care of by the `ExportKeyWrapped()` helper function
    // invoked below. See its definition for more information on this process.

    // Retrieve the RSA private key we want to import.
    PBYTE rsa_private_key_data = get_rsa_private_key_data_ptr(keylen);
    DWORD rsa_private_key_data_len = get_rsa_private_key_data_len(keylen);
    RETURN_HR_IF_MSG(E_UNEXPECTED, rsa_private_key_data == NULL, "Failed get_rsa_private_key_data_ptr");
    RETURN_HR_IF_MSG(E_UNEXPECTED, rsa_private_key_data_len == 0, "Failed get_rsa_private_key_data_len");

    RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(WrapKey(
                             rsa_private_key_data,
                             rsa_private_key_data_len,
                             unwrap_key_data.data(),
                             (DWORD)unwrap_key_data.size(),
                             hash_alg,
                             outBlob)),
                         "Failed ExportKeyWrapped");

    return S_OK;
}

// Helper function that searches the command-line arguments provided by the
// user for an RSA key length specification.
RsaKeyLength parse_key_len(_In_ int argc, _In_reads_(argc) char **argv)
{
    RsaKeyLength result = RsaKeyLength::RSA_KEY_LENGTH_2048;

    // Iterate through each command-line argument (skipping the first, which is
    // the executable path) and look for key lengths. Convert strings to
    // lowercase to allow for case insensitive matches.
    for (int i = 1; i < argc; i++)
    {
        char *arg = argv[i];

        // Make a copy of the argument string, and convert it to lowercase
        std::string str(arg);
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);

        if (str == "2048" || str == "2k")
        {
            result = RsaKeyLength::RSA_KEY_LENGTH_2048;
        }
        else if (str == "3072" || str == "3k")
        {
            result = RsaKeyLength::RSA_KEY_LENGTH_3072;
        }
        else if (str == "4096" || str == "4k")
        {
            result = RsaKeyLength::RSA_KEY_LENGTH_4096;
        }
    }

    return result;
}

int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    try
    {
        printf("AziHSM Demonstration: RSA Key Import --> RSA Encrypt --> RSA Decrypt\n");
        printf("====================================================================\n");

        // Parse the RSA key length from the command-line
        RsaKeyLength keylen = parse_key_len(argc, argv);
        switch (keylen)
        {
        case RsaKeyLength::RSA_KEY_LENGTH_2048:
            printf("The imported RSA key will have a length of 2048.\n");
            break;
        case RsaKeyLength::RSA_KEY_LENGTH_3072:
            printf("The imported RSA key will have a length of 3072.\n");
            break;
        case RsaKeyLength::RSA_KEY_LENGTH_4096:
            printf("The imported RSA key will have a length of 4096.\n");
            break;
        default:
            fprintf(stderr, "Unexpected RSA key length provided.\n");
            return E_FAIL;
        }

        wil::unique_ncrypt_prov provider;
        wil::unique_ncrypt_key importKey;

        RETURN_IF_FAILED_MSG(open_provider_and_key(provider, importKey), "Failed open_provider_and_key");

        // -------------------- Step 1 - Import the RSA Key --------------------- //

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
        std::vector<BYTE> blob_data;

        RETURN_IF_FAILED_MSG(wrap_rsa_key(
                                 provider.get(),
                                 importKey.get(),
                                 keylen,
                                 NCRYPT_SHA256_ALGORITHM,
                                 blob_data),
                             "Failed wrap_rsa_key");
        RETURN_HR_IF_MSG(E_UNEXPECTED, blob_data.empty(), "Wrapped key blob is empty");
        printf("Created wrapped RSA key blob: %zu bytes of data.\n", blob_data.size());

        // Next, take the blob and import into the AziHSM as an RSA key.
        wil::unique_ncrypt_key importedKey;

        RETURN_IF_FAILED_MSG(import_bcrypt_wrapped_key(
                                 provider.get(),
                                 importKey.get(),
                                 blob_data.data(),
                                 (DWORD)blob_data.size(),
                                 KeyType::KEY_TYPE_RSA,
                                 -1, // No need to specify key size for RSA key during import
                                 NCRYPT_ALLOW_DECRYPT_FLAG,
                                 importedKey),
                             "Failed import_bcrypt_wrapped_key");
        printf("Successfully imported key into AziHSM. Got handle: %Iu\n",
               importedKey.get());

        // --------------- Step 2 - Generate & Encrypt Plaintext ---------------- //
        printf("\nStep 2: Encrypt Decrypt test"
               "\n-------------------------\n");

        RETURN_IF_FAILED_MSG(encrypt_decrypt_rsa(
                                 importedKey.get(),
                                 NCRYPT_SHA384_ALGORITHM,
                                 "Some messsage you wish to encrypt"),
                             "Failed encrypt_decrypt_rsa");

        printf("Demo completed!\n");

        return S_OK;
    }
    catch (const std::exception &ex)
    {
        fprintf(stderr, "Unhandled exception in RSA sample: %s\n", ex.what());
        return E_FAIL;
    }
    catch (...)
    {
        fprintf(stderr, "Unhandled unknown exception in RSA sample\n");
        return E_FAIL;
    }
}
