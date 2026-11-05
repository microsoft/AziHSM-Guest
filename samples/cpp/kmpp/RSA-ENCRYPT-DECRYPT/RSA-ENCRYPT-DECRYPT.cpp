// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    See README.md in this folder (and the KMPP guide it links to).
//
// This sample demonstrates AziHSM through KMPP in the following scenario:
//
// 1. Import an embedded RSA test key (2048, 3072 or 4096 bits) into KMPP with
//    the ENCRYPT usage; the private key is materialized inside AziHSM.
// 2. RSA-OAEP encrypt a message with the public key (in process, no HSM call).
// 3. RSA-OAEP decrypt the ciphertext with the private key, inside AziHSM.
// 4. Verify that the decrypted message matches the original.
//
// Usage: RSA-ENCRYPT-DECRYPT [size]   size: 2048 (default), 3072, 4096 (2k/3k/4k)
//
// The KMPP and OpenSSL specifics live in include/Kmpp; to see the high-level
// steps of this scenario, study `run`.

#include <cstdio>

#include "Kmpp/SampleUtils.h"

namespace
{

void run(const char* size_arg)
{
    using namespace kmpp;

    // ---------------- Step 1 - Import the RSA key into AziHSM ----------------- //
    // Pick the embedded test key for the requested size, then import it into KMPP
    // with the ENCRYPT usage only (AziHSM rejects the combined default usage).
    // KMPP materializes the private key inside AziHSM; the sample only keeps an
    // opaque KeyID and a kmppprovider-backed EVP_PKEY.
    const TestKey key = select_rsa(size_arg);
    const sample::LoadedKey loaded = sample::import_and_load(key, KEYISO_KEY_USAGE_ENCRYPT_FLAG, "ENCRYPT");
    const Bytes message = sample::message_bytes();

    // ------------------ Step 2 - Encrypt with the public key ------------------- //
    // Whoever encrypts normally holds only the public key, so derive a plain public
    // key and encrypt with OpenSSL's default provider. This also checks that AziHSM
    // decrypts standard RSA-OAEP ciphertext, not only ciphertext made by KMPP.
    std::printf("[step 2] encrypt with public key (RSA-OAEP)\n");
    const UniquePkey public_key = public_from_key(loaded.pkey.get());
    const Bytes ciphertext = rsa_oaep_encrypt(public_key.get(), message);
    std::printf("  encrypted %zu bytes -> %zu bytes ciphertext\n", message.size(), ciphertext.size());
    sample::print_hex("ciphertext", ciphertext);

    // ------------------ Step 3 - Decrypt inside AziHSM ------------------------- //
    // Decryption needs the private key, so kmppprovider routes it through libkmpp
    // to AziHSM. The OAEP hash stays at the OpenSSL default (SHA-1), the only one
    // KMPP supports for decrypt.
    std::printf("[step 3] decrypt with private key -> KMPP -> AziHSM\n");
    const Bytes plaintext = rsa_oaep_decrypt(loaded.pkey.get(), ciphertext);
    std::printf("  decrypted -> %zu bytes\n", plaintext.size());

    // ------------------ Step 4 - Verify the round-trip ------------------------- //
    std::printf("[step 4] verify round-trip\n");
    if (plaintext != message)
    {
        throw Error("round-trip mismatch: decrypted != original");
    }

    std::printf("\n[PASS] RSA-OAEP round-trip verified — private-key op ran inside AziHSM.\n");
}

} // namespace

int main(int argc, char** argv)
{
    return kmpp::sample::run_sample(argc, argv,
                                    "Usage: RSA-ENCRYPT-DECRYPT [size]   # size: 2048 (default), 3072, 4096",
                                    "KMPP x AziHSM: RSA-OAEP encrypt -> decrypt", run);
}
