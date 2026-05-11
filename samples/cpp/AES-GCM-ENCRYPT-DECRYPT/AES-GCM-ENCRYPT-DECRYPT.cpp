// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check `README.md` for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Generate an AES-GCM key
// 2. Use the AES-GCM key to encrypt data.
// 3. Use the AES-GCM key to decrypt data.
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

#include <windows.h>
#include <ncrypt.h>

#include <cstdio>
#include <vector>
#include <exception>

#include <wil/resource.h>

#include "AziHSM/AziHSM.h"
#include "Utils/Utils.h"
#include "Utils/CryptoUtils.h"

// Definitions for AES-GCM encryption parameter lengths.
#define AES_GCM_AAD_LEN 32

int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    try
    {
        set_wil_log_callback();

        printf("AziHSM Demonstration: AES-GCM Key Gen --> AES-GCM Encrypt --> AES-GCM Decrypt\n");
        printf("=============================================================================\n");

        // Open a handle to the AziHSM via the NCrypt API.
        wil::unique_ncrypt_prov provider;
        RETURN_IF_FAILED_MSG(NCryptOpenStorageProvider(provider.put(), AZIHSM_KSP_NAME, 0), "Failed NCryptOpenStorageProvider");
        printf("Opened NCrypt Storage Provider handle: %Iu\n", provider.get());

        // ----------------- Step 1 - Generate the AES-GCM Key ------------------ //
        printf("\nStep 1: Generate AES-GCM Key"
               "\n----------------------------\n");

        // Start by creating an AES key handle.
        wil::unique_ncrypt_key encdec_key;
        RETURN_IF_FAILED_MSG(NCryptCreatePersistedKey(
                                 provider.get(),
                                 encdec_key.put(),
                                 BCRYPT_AES_ALGORITHM,
                                 NULL,
                                 0,
                                 0),
                             "Failed NCryptCreatePersistedKey");
        printf("Created AES key handle: %Iu\n", encdec_key.get());

        // Next, set the chaining mode of the AES key to GCM.
        RETURN_IF_FAILED_MSG(NCryptSetProperty(
                                 encdec_key.get(),
                                 NCRYPT_CHAINING_MODE_PROPERTY,
                                 (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                                 (DWORD)(sizeof(BCRYPT_CHAIN_MODE_GCM)),
                                 0),
                             "Failed NCryptSetProperty NCRYPT_CHAINING_MODE_PROPERTY to BCRYPT_CHAIN_MODE_GCM");

        // Next, set the length of the AES key to 256 bits (32 bytes).
        // For AES-GCM, AziHSM supports only 256-bit keys.
        RETURN_IF_FAILED_MSG(NCryptSetProperty(
                                 encdec_key.get(),
                                 NCRYPT_LENGTH_PROPERTY,
                                 (PBYTE)&AZIHSM_AES_GCM_KEY_LENGTH_BITS,
                                 (DWORD)sizeof(DWORD),
                                 0),
                             "Failed NCryptSetProperty NCRYPT_LENGTH_PROPERTY to %d", AZIHSM_AES_GCM_KEY_LENGTH_BITS);

        // Finally, we complete the key creation process by finalizing the key via
        // `NCryptFinalizeKey`.
        RETURN_IF_FAILED_MSG(NCryptFinalizeKey(encdec_key.get(), 0), "Failed NCryptFinalizeKey");

        // --------------- Step 2 - Generate & Encrypt Plaintext ---------------- //
        printf("\nStep 2: Encrypt Plaintext"
               "\n-------------------------\n");
        // Size of plaintext.
        size_t plaintext_len = 0;

        // For this demo, we'll select a random length for the plaintext. Plaintext
        // lengths can be any length for AES-GCM encryption (no need to match the
        // block size).
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(random_uint_range(&plaintext_len, 64, 256)), "Failed random_uint_range");

        // Allocate a buffer of plaintext to encrypt, and fill it with random
        // bytes.
        std::vector<BYTE> plaintext(plaintext_len);
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(plaintext.data(), plaintext.size())), "Failed randomize_buffer for plaintext");
        std::cout << "Plaintext:\n\t" << buffer_to_hex(plaintext.data(), plaintext_len) << std::endl;

        // We also need to generate a random AAD (Additional Authenticated Data) for
        // AES-GCM encryption.
        std::vector<BYTE> aad(AES_GCM_AAD_LEN);
        RETURN_IF_FAILED_MSG(HRESULT_FROM_NT(randomize_buffer(aad.data(), aad.size())), "Failed randomize_buffer for AAD");

        // Additionally, we need to allocate a buffer to store the AES-GCM IV
        // (Initialization Vector).
        //
        // For AES-GCM encryption operations, the AziHSM device will generate its
        // own IV internally. Thus, we do not need to generate one ourselves.
        // However, we do need to allocate a buffer and pass it into
        // `NCryptEncrypt` to give the AziHSM KSP a place to write th IV outputted
        // by the AziHSM device.
        //
        // Additionally, the AziHSM KSP requires that the IV buffer be initialized
        // to all zeroes as an acknowledgement by the user that an IV is not
        // provided by the user.
        std::vector<BYTE> iv(AZIHSM_AES_GCM_IV_LENGTH_BYTES, 0);

        std::cout << "AAD:\n\t" << buffer_to_hex(aad.data(), aad.size()) << std::endl;
        std::cout << "Pre-Encryption IV:\n\t" << buffer_to_hex(iv.data(), iv.size()) << std::endl
                  << std::endl;

        // Next, invoke the helper function to encrypt the plaintext, using the
        // AES-GCM key we just created.
        //
        // Encryption will do the following:
        //
        // 1. The AziHSM will generate a random IV internally, and the bytes will
        //    be written out to our `iv` buffer.
        // 2. The AziHSM will generate a tag internally.
        // 3. The ciphertext will be generated.

        std::vector<BYTE> tag;
        std::vector<BYTE> ciphertext;

        RETURN_HR_IF_MSG(E_INVALIDARG, plaintext.empty(), "Plaintext buffer must not be empty");
        RETURN_HR_IF_MSG(E_INVALIDARG, aad.size() != AES_GCM_AAD_LEN, "AAD buffer has invalid length: %zu", aad.size());
        RETURN_HR_IF_MSG(E_INVALIDARG, iv.size() != AZIHSM_AES_GCM_IV_LENGTH_BYTES, "IV buffer has invalid length: %zu", iv.size());

        RETURN_IF_FAILED_MSG(encrypt_aes_gcm(
                                 encdec_key.get(),
                                 plaintext,
                                 aad,
                                 iv,
                                 tag,
                                 ciphertext),
                             "Failed encrypt");
        printf("Successfully encrypted plaintext: %zu bytes of ciphertext.\n",
               ciphertext.size());

        std::cout << "Ciphertext:\n\t" << buffer_to_hex(ciphertext.data(), ciphertext.size()) << std::endl;
        std::cout << "Post-Encryption IV:\n\t" << buffer_to_hex(iv.data(), iv.size()) << std::endl;
        std::cout << "Post-Encryption Tag:\n\t" << buffer_to_hex(tag.data(), tag.size()) << std::endl;

        // ------------------ Step 3 - Decrypt the Ciphertext ------------------- //
        printf("\nStep 3: Decrypt Ciphertext"
               "\n--------------------------\n");

        // Invoke the helper function to decrypt the plaintext, using the AES-GCM
        // key we just created.
        std::vector<BYTE> decrypted;
        RETURN_HR_IF_MSG(E_INVALIDARG, ciphertext.empty(), "Ciphertext buffer must not be empty");
        RETURN_HR_IF_MSG(E_INVALIDARG, tag.empty(), "Tag buffer must not be empty");
        RETURN_HR_IF_MSG(E_INVALIDARG, iv.size() != AZIHSM_AES_GCM_IV_LENGTH_BYTES, "IV buffer has invalid length: %zu", iv.size());

        RETURN_IF_FAILED_MSG(decrypt_aes_gcm(
                                 encdec_key.get(),
                                 ciphertext,
                                 aad,
                                 iv,
                                 tag,
                                 decrypted),
                             "Failed decrypt");
        printf("Successfully decrypted ciphertext: %zu bytes of plaintext.\n",
               decrypted.size());

        // Display the ciphertext as a hex string:
        std::cout << "Decrypted plaintext:\n\t" << buffer_to_hex(decrypted.data(), decrypted.size()) << std::endl;

        RETURN_HR_IF_MSG(E_UNEXPECTED, plaintext != decrypted, "The decrypted ciphertext does not match the original plaintext");

        printf("The decrypted ciphertext matches the original plaintext!\n");

        return S_OK;
    }
    catch (const std::exception &ex)
    {
        fprintf(stderr, "Unhandled exception in AES-GCM sample: %s\n", ex.what());
        return E_FAIL;
    }
    catch (...)
    {
        fprintf(stderr, "Unhandled unknown exception in AES-GCM sample\n");
        return E_FAIL;
    }
}
