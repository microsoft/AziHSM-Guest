// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate an AES-XTS key
// 2. Use the AES-XTS key to encrypt data.
// 3. Use the AES-XTS key to decrypt data.
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

#include <windows.h>
#include <ncrypt.h>

#include <cstdio>
#include <vector>
#include <iostream>

#include <wil/resource.h>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"

// Helper function that encrypts the provided plaintext using the provided key
// handle.
static HRESULT encrypt(_In_ const NCRYPT_KEY_HANDLE &key,
                       _In_ const std::vector<BYTE> &plaintext,
                       _In_ const std::vector<BYTE> &tweak,
                       _Out_ std::vector<BYTE> &outResult)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, key == 0, "Invalid key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, plaintext.empty(), "Plaintext buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, plaintext.size() % AZIHSM_AES_XTS_BLOCK_LENGTH_BYTES != 0,
                     "Plaintext size must be a multiple of %u bytes", AZIHSM_AES_XTS_BLOCK_LENGTH_BYTES);
    RETURN_HR_IF_MSG(E_INVALIDARG, tweak.size() != AZIHSM_AES_XTS_TWEAK_LENGTH_BYTES,
                     "Tweak buffer has invalid length: %zu", tweak.size());

    // -------------------------- Parameter Setup --------------------------- //
    // Before calling `NCryptEncrypt`, we need to set up parameter objects that
    // contain information needed by the AES-XTS algorithm.

    // Create a `NCRYPT_CIPHER_PADDING_INFO` struct to hold the AES-XTS
    // parameters (primarily the tweak value). This is the primary object we
    // pass into `NCryptEncrypt`.
    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.dwFlags = 0;
    pinfo.pbIV = (PBYTE)tweak.data();
    pinfo.cbIV = (ULONG)tweak.size();
    pinfo.pbOtherInfo = NULL;
    pinfo.cbOtherInfo = 0;

    // ----------------------- Performing Encryption ------------------------ //
    // Call `NCryptEncrypt` once, to determine how many bytes are needed to
    // store the ciphertext.
    DWORD ciphertext_len = 0;
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
                             key,
                             (PBYTE)plaintext.data(),
                             (DWORD)plaintext.size(),
                             &pinfo,
                             NULL,
                             0,
                             &ciphertext_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 1st NCryptEncrypt");

    // Allocate a buffer to store the ciphertext, then call `NCryptEncrypt` a
    // second time to generate it and store the result.
    std::vector<BYTE> ciphertext(ciphertext_len);
    RETURN_IF_FAILED_MSG(NCryptEncrypt(
                             key,
                             (PBYTE)plaintext.data(),
                             (DWORD)plaintext.size(),
                             &pinfo,
                             ciphertext.data(),
                             (DWORD)ciphertext.size(),
                             &ciphertext_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 2nd NCryptEncrypt");

    outResult = std::move(ciphertext);
    return S_OK;
}

// Helper function that decrypts the provided ciphertext using the provided key
// handle.
static HRESULT decrypt(_In_ const NCRYPT_KEY_HANDLE &key,
                       _In_ const std::vector<BYTE> &ciphertext,
                       _In_ const std::vector<BYTE> &tweak,
                       _Out_ std::vector<BYTE> &outResult)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, key == 0, "Invalid key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, ciphertext.empty(), "Ciphertext buffer must not be empty");
    RETURN_HR_IF_MSG(E_INVALIDARG, ciphertext.size() % AZIHSM_AES_XTS_BLOCK_LENGTH_BYTES != 0,
                     "Ciphertext size must be a multiple of %u bytes", AZIHSM_AES_XTS_BLOCK_LENGTH_BYTES);
    RETURN_HR_IF_MSG(E_INVALIDARG, tweak.size() != AZIHSM_AES_XTS_TWEAK_LENGTH_BYTES,
                     "Tweak buffer has invalid length: %zu", tweak.size());

    // Create a `NCRYPT_CIPHER_PADDING_INFO` struct to hold the AES-XTS
    // parameters (primarily the tweak value). This is the primary object we
    // pass into `NCryptDecrypt`.
    NCRYPT_CIPHER_PADDING_INFO pinfo;
    pinfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);
    pinfo.dwFlags = 0;
    pinfo.pbIV = (PBYTE)tweak.data();
    pinfo.cbIV = (ULONG)tweak.size();
    pinfo.pbOtherInfo = NULL;
    pinfo.cbOtherInfo = 0;

    // ----------------------- Performing Decryption ------------------------ //
    // Call `NCryptDecrypt` once, to determine how many bytes are needed to
    // store the plaintext.
    DWORD decrypted_len = 0;
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
                             key,
                             (PBYTE)ciphertext.data(),
                             (DWORD)ciphertext.size(),
                             &pinfo,
                             NULL,
                             0,
                             &decrypted_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 1st NCryptDecrypt");

    // Allocate a buffer to store the plaintext, then call `NCryptDecrypt` a
    // second time to generate it and store the result.
    std::vector<BYTE> decrypted(decrypted_len);
    RETURN_IF_FAILED_MSG(NCryptDecrypt(
                             key,
                             (PBYTE)ciphertext.data(),
                             (DWORD)ciphertext.size(),
                             &pinfo,
                             decrypted.data(),
                             (DWORD)decrypted.size(),
                             &decrypted_len,
                             NCRYPT_PAD_CIPHER_FLAG),
                         "Failed 2nd NCryptDecrypt");

    outResult = std::move(decrypted);
    return S_OK;
}

int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    try
    {
        set_wil_log_callback();

        printf("AziHSM Demonstration: AES-XTS Key Gen --> AES-XTS Encrypt --> AES-XTS Decrypt\n");
        printf("=============================================================================\n");

        // Open a handle to the AziHSM via the NCrypt API.
        wil::unique_ncrypt_prov provider;
        RETURN_IF_FAILED_MSG(NCryptOpenStorageProvider(provider.put(), AZIHSM_KSP_NAME, 0), "Failed NCryptOpenStorageProvider");
        printf("Opened NCrypt Storage Provider handle: %Iu\n", provider.get());

        // ----------------- Step 1 - Generate the AES-XTS Key ------------------ //
        printf("\nStep 1: Generate AES-XTS Key"
               "\n----------------------------\n");

        // Start by creating an AES key handle.
        wil::unique_ncrypt_key encdec_key;
        RETURN_IF_FAILED_MSG(NCryptCreatePersistedKey(
                                 provider.get(),
                                 encdec_key.put(),
                                 BCRYPT_XTS_AES_ALGORITHM,
                                 NULL,
                                 0,
                                 0),
                             "Failed NCryptCreatePersistedKey");
        printf("Created AES key handle: %Iu\n", encdec_key.get());

        // Next, set the length of the AES key to 512 bits (64 bytes).
        // For AES-XTS, AziHSM supports only 512-bit keys.
        RETURN_IF_FAILED_MSG(NCryptSetProperty(
                                 encdec_key.get(),
                                 NCRYPT_LENGTH_PROPERTY,
                                 (PBYTE)&AZIHSM_AES_XTS_KEY_LENGTH_BITS,
                                 (DWORD)sizeof(DWORD),
                                 0),
                             "Failed NCryptSetProperty NCRYPT_LENGTH_PROPERTY to %d", AZIHSM_AES_XTS_KEY_LENGTH_BITS);

        // Finally, we complete the key creation process by finalizing the key via
        // `NCryptFinalizeKey`.
        RETURN_IF_FAILED_MSG(NCryptFinalizeKey(encdec_key.get(), 0), "Failed NCryptFinalizeKey");
        printf("Finalized AES-XTS key successfully.\n");

        // --------------- Step 2 - Generate & Encrypt Plaintext ---------------- //
        printf("\nStep 2: Encrypt Plaintext"
               "\n-------------------------\n");

        // AziHSM expects plaintext lengths to be multiples of the AES-XTS block
        // size (`AZIHSM_AES_XTS_BLOCK_LENGTH_BYTES`). So, for this demo, we'll
        // generate a random buffer length that satisfies this requirement.
        size_t plaintext_len = 0;
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(random_uint_range_multiple(
                                 &plaintext_len,
                                 64,
                                 256,
                                 AZIHSM_AES_XTS_BLOCK_LENGTH_BYTES)),
                             "Failed random_uint_range_multiple");
        printf("Plaintext length chosen: %zu bytes.\n", plaintext_len);

        // Allocate a buffer of plaintext to encrypt, and fill it with random
        // bytes.
        std::vector<BYTE> plaintext(plaintext_len);
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(plaintext.data(), plaintext.size())), "Failed randomize_buffer for plaintext");
        std::cout << "Plaintext:\n\t" << buffer_to_hex(plaintext.data(), plaintext.size()) << std::endl;

        // Additionally, we need to allocate a buffer to store the AES-XTS tweak
        // value.
        std::vector<BYTE> tweak(AZIHSM_AES_XTS_TWEAK_LENGTH_BYTES);
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(tweak.data(), tweak.size())), "Failed randomize_buffer for tweak");
        std::cout << "Tweak buffer:\n\t" << buffer_to_hex(tweak.data(), tweak.size()) << std::endl;

        // Next, invoke the helper function to encrypt the plaintext, using the
        // AES-XTS key we just created.
        std::vector<BYTE> ciphertext;
        RETURN_IF_FAILED_MSG(encrypt(
                                 encdec_key.get(),
                                 plaintext,
                                 tweak,
                                 ciphertext),
                             "Failed encrypt");
        printf("Successfully encrypted plaintext: %zu bytes of ciphertext.\n",
               ciphertext.size());

        std::cout << "Ciphertext:\n\t" << buffer_to_hex(ciphertext.data(), ciphertext.size()) << std::endl;

        // ------------------ Step 3 - Decrypt the Ciphertext ------------------- //
        printf("\nStep 3: Decrypt Ciphertext"
               "\n--------------------------\n");

        // Invoke the helper function to decrypt the plaintext, using the AES-XTS
        // key we just created.
        std::vector<BYTE> decrypted;
        RETURN_IF_FAILED_MSG(decrypt(
                                 encdec_key.get(),
                                 ciphertext,
                                 tweak,
                                 decrypted),
                             "Failed decrypt");
        printf("Successfully decrypted ciphertext: %zu bytes of plaintext.\n",
               decrypted.size());

        std::cout << "Decrypted plaintext:\n\t" << buffer_to_hex(decrypted.data(), decrypted.size()) << std::endl;

        RETURN_HR_IF_MSG(E_UNEXPECTED, plaintext != decrypted, "The decrypted ciphertext does not match the original plaintext");

        printf("The decrypted ciphertext matches the original plaintext!\n");

        return S_OK;
    }
    catch (const std::exception &ex)
    {
        fprintf(stderr, "Unhandled exception in AES-XTS sample: %s\n", ex.what());
        return E_FAIL;
    }
    catch (...)
    {
        fprintf(stderr, "Unhandled unknown exception in AES-XTS sample\n");
        return E_FAIL;
    }
}
