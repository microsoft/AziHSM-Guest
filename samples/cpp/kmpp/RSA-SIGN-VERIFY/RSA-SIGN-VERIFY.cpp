// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    See README.md in this folder (and the KMPP guide it links to).
//
// This sample demonstrates AziHSM through KMPP in the following scenario:
//
// 1. Import an embedded RSA test key (2048, 3072 or 4096 bits) into KMPP with
//    the SIGN usage; the private key is materialized inside AziHSM.
// 2. Sign a message inside AziHSM with RSA PKCS#1 v1.5, then with RSA-PSS
//    (salt length == hash length).
// 3. Verify each signature with the public key (OpenSSL default provider).
//
// Usage: RSA-SIGN-VERIFY [size]   size: 2048 (default), 3072, 4096 (2k/3k/4k)
//
// The KMPP and OpenSSL specifics live in include/Kmpp; to see the high-level
// steps of this scenario, study `run`.

#include <cstdio>
#include <initializer_list>
#include <string>

#include "Kmpp/SampleUtils.h"

namespace
{

void run(const char* size_arg)
{
    using namespace kmpp;

    // ---------------- Step 1 - Import the RSA key into AziHSM ----------------- //
    // Pick the embedded test key for the requested size, then import it into KMPP
    // with the SIGN usage only (AziHSM rejects the combined default usage). KMPP
    // materializes the private key inside AziHSM; the sample only keeps an opaque
    // KeyID and a kmppprovider-backed EVP_PKEY.
    const TestKey key = select_rsa(size_arg);
    const sample::LoadedKey loaded = sample::import_and_load(key, KEYISO_KEY_USAGE_SIGN_FLAG, "SIGN");

    // Derive a plain public key (OpenSSL default provider), so verification is
    // independent of KMPP and never touches the device.
    const UniquePkey public_key = public_from_key(loaded.pkey.get());
    const Bytes message = sample::message_bytes();

    // --------------- Step 2 - Sign inside AziHSM, verify in process ------------ //
    // Signing is anchored to the key's provider, so it runs on AziHSM while the
    // SHA-256 digest comes from the default provider. PSS uses salt length ==
    // hash length, which AziHSM enforces.
    for (const SigScheme scheme : {SigScheme::RsaPkcs1, SigScheme::RsaPss})
    {
        std::printf("[sign/verify] %s\n", to_string(scheme));
        const Bytes signature = digest_sign_sha256(loaded.pkey.get(), message, scheme);
        std::printf("  signed %zu bytes -> %zu byte signature\n", message.size(), signature.size());
        sample::print_hex("signature", signature);

        // ------------- Step 3 - Verify with the public key only ---------------- //
        if (!digest_verify_sha256(public_key.get(), message, signature, scheme))
        {
            throw Error(std::string(to_string(scheme)) + " signature failed to verify");
        }
        std::printf("  verified OK\n");
    }

    std::printf("\n[PASS] %s sign/verify (PKCS#1 v1.5 + PSS) — signatures produced inside AziHSM.\n", key.name);
}

} // namespace

int main(int argc, char** argv)
{
    return kmpp::sample::run_sample(argc, argv,
                                    "Usage: RSA-SIGN-VERIFY [size]   # size: 2048 (default), 3072, 4096",
                                    "KMPP x AziHSM: RSA sign -> verify (PKCS#1 v1.5 + PSS)", run);
}
