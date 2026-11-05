// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Device-free tests for the shared KMPP sample helpers (`make check`). They need
// OpenSSL only - no KMPP and no AziHSM device - so they run on any Linux host.
//
// The crypto wrappers are exercised with plain software keys decoded from the
// embedded test keys; on a device the same wrappers run against KMPP-backed keys.

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <initializer_list>
#include <string>

#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "Kmpp/SampleUtils.h"

namespace
{

int g_failures = 0;

#define EXPECT(condition)                                                                \
    do                                                                                   \
    {                                                                                    \
        if (!(condition))                                                                \
        {                                                                                \
            std::fprintf(stderr, "    expectation failed (%s:%d): %s\n", __FILE__, __LINE__, \
                         #condition);                                                    \
            ++g_failures;                                                                \
        }                                                                                \
    } while (0)

struct ExpectedKey
{
    const char* arg;
    const char* name;
    int bits;
};

constexpr ExpectedKey kRsaKeys[] = {
    {"2048", "RSA-2048", 2048},
    {"3072", "RSA-3072", 3072},
    {"4096", "RSA-4096", 4096},
};

// Decodes an embedded test key into a plain software EVP_PKEY.
kmpp::UniquePkey decode(const kmpp::TestKey& key)
{
    const unsigned char* cursor = key.der;
    kmpp::UniquePkey pkey(d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(key.size)));
    if (pkey == nullptr)
    {
        throw kmpp::Error(std::string("cannot decode ") + key.name);
    }
    return pkey;
}

// Returns true if `fn` throws kmpp::Error.
template <typename Fn>
bool throws_error(Fn&& fn)
{
    try
    {
        fn();
    }
    catch (const kmpp::Error&)
    {
        return true;
    }
    return false;
}

void select_rsa_maps_sizes_and_default()
{
    EXPECT(std::string(kmpp::select_rsa(nullptr).name) == "RSA-2048");
    EXPECT(std::string(kmpp::select_rsa("2k").name) == "RSA-2048");
    EXPECT(std::string(kmpp::select_rsa("3K").name) == "RSA-3072");
    EXPECT(std::string(kmpp::select_rsa("4096").name) == "RSA-4096");

    bool rejected = false;
    try
    {
        kmpp::select_rsa("1024");
    }
    catch (const kmpp::Error&)
    {
        rejected = true;
    }
    EXPECT(rejected);
}

void embedded_keys_decode_with_expected_size()
{
    for (const ExpectedKey& expected : kRsaKeys)
    {
        const kmpp::TestKey key = kmpp::select_rsa(expected.arg);
        EXPECT(std::string(key.name) == expected.name);
        EXPECT(key.size > 0 && key.der[0] == 0x30); // DER SEQUENCE
        EXPECT(EVP_PKEY_get_bits(decode(key).get()) == expected.bits);
    }
}

void pfx_round_trips_key_and_self_signed_cert()
{
    for (const ExpectedKey& expected : kRsaKeys)
    {
        const kmpp::TestKey key = kmpp::select_rsa(expected.arg);
        const kmpp::Bytes pfx = kmpp::detail::build_self_signed_pfx(key.der, key.size);

        const unsigned char* cursor = pfx.data();
        kmpp::detail::UniquePkcs12 p12(d2i_PKCS12(nullptr, &cursor, static_cast<long>(pfx.size())));
        EXPECT(p12 != nullptr);
        if (p12 == nullptr)
        {
            continue;
        }

        EVP_PKEY* parsed_key = nullptr;
        X509* parsed_cert = nullptr;
        EXPECT(PKCS12_parse(p12.get(), kmpp::detail::kPfxPassword, &parsed_key, &parsed_cert, nullptr) == 1);
        kmpp::UniquePkey owned_key(parsed_key);
        kmpp::detail::UniqueX509 owned_cert(parsed_cert);
        if (owned_key == nullptr || owned_cert == nullptr)
        {
            continue;
        }

        EXPECT(EVP_PKEY_eq(owned_key.get(), decode(key).get()) == 1);
        EXPECT(X509_NAME_cmp(X509_get_subject_name(owned_cert.get()), X509_get_issuer_name(owned_cert.get())) == 0);
        EXPECT(X509_verify(owned_cert.get(), owned_key.get()) == 1);
    }
}

void rsa_oaep_round_trips()
{
    // Same flow as the sample: encrypt with a derived public-only key, decrypt with the private key.
    const kmpp::UniquePkey pkey = decode(kmpp::select_rsa(nullptr));
    const kmpp::UniquePkey public_key = kmpp::public_from_key(pkey.get());
    const kmpp::Bytes message = kmpp::sample::message_bytes();

    const kmpp::Bytes ciphertext = kmpp::rsa_oaep_encrypt(public_key.get(), message);
    EXPECT(ciphertext.size() == 256);
    EXPECT(kmpp::rsa_oaep_decrypt(pkey.get(), ciphertext) == message);

    // A public-only key cannot decrypt.
    EXPECT(throws_error([&] { kmpp::rsa_oaep_decrypt(public_key.get(), ciphertext); }));
}

void sign_verify_accepts_valid_and_rejects_tampered()
{
    const kmpp::UniquePkey pkey = decode(kmpp::select_rsa(nullptr));
    const kmpp::UniquePkey public_key = kmpp::public_from_key(pkey.get());
    const kmpp::Bytes message = kmpp::sample::message_bytes();

    for (const kmpp::SigScheme scheme : {kmpp::SigScheme::RsaPkcs1, kmpp::SigScheme::RsaPss})
    {
        const kmpp::Bytes signature = kmpp::digest_sign_sha256(pkey.get(), message, scheme);
        EXPECT(kmpp::digest_verify_sha256(public_key.get(), message, signature, scheme));

        kmpp::Bytes tampered_signature = signature;
        tampered_signature[tampered_signature.size() / 2] ^= 0x01;
        EXPECT(!kmpp::digest_verify_sha256(public_key.get(), message, tampered_signature, scheme));

        kmpp::Bytes tampered_message = message;
        tampered_message[0] ^= 0x01;
        EXPECT(!kmpp::digest_verify_sha256(public_key.get(), tampered_message, signature, scheme));
    }

    // A PSS signature must not verify as PKCS#1 v1.5.
    const kmpp::Bytes pss = kmpp::digest_sign_sha256(pkey.get(), message, kmpp::SigScheme::RsaPss);
    EXPECT(!kmpp::digest_verify_sha256(public_key.get(), message, pss, kmpp::SigScheme::RsaPkcs1));
}

void helpers_reject_invalid_arguments()
{
    const kmpp::UniquePkey pkey = decode(kmpp::select_rsa(nullptr));
    const kmpp::Bytes message = kmpp::sample::message_bytes();
    const kmpp::Bytes empty;

    EXPECT(throws_error([] { kmpp::detail::build_self_signed_pfx(nullptr, 0); }));
    EXPECT(throws_error([] { kmpp::import_key_der(0, nullptr, 0); })); // usage flag checked before libkmpp is loaded
    EXPECT(throws_error([&] { kmpp::rsa_oaep_encrypt(pkey.get(), empty); }));
    EXPECT(throws_error([&] { kmpp::rsa_oaep_decrypt(nullptr, message); }));
    EXPECT(throws_error([&] { kmpp::digest_sign_sha256(nullptr, message, kmpp::SigScheme::RsaPss); }));
    EXPECT(throws_error([&] { kmpp::digest_verify_sha256(pkey.get(), message, empty, kmpp::SigScheme::RsaPss); }));
    EXPECT(throws_error([] { kmpp::public_from_key(nullptr); }));
}

struct TestCase
{
    const char* name;
    void (*run)();
};

constexpr TestCase kTests[] = {
    {"select_rsa_maps_sizes_and_default", select_rsa_maps_sizes_and_default},
    {"embedded_keys_decode_with_expected_size", embedded_keys_decode_with_expected_size},
    {"pfx_round_trips_key_and_self_signed_cert", pfx_round_trips_key_and_self_signed_cert},
    {"rsa_oaep_round_trips", rsa_oaep_round_trips},
    {"sign_verify_accepts_valid_and_rejects_tampered", sign_verify_accepts_valid_and_rejects_tampered},
    {"helpers_reject_invalid_arguments", helpers_reject_invalid_arguments},
};

} // namespace

int main()
{
    int failed_tests = 0;
    for (const TestCase& test : kTests)
    {
        const int failures_before = g_failures;
        try
        {
            test.run();
        }
        catch (const std::exception& ex)
        {
            std::fprintf(stderr, "    unexpected exception: %s\n", ex.what());
            ++g_failures;
        }
        const bool passed = g_failures == failures_before;
        failed_tests += passed ? 0 : 1;
        std::printf("[%s] %s\n", passed ? " OK " : "FAIL", test.name);
    }

    const int total = static_cast<int>(sizeof(kTests) / sizeof(kTests[0]));
    std::printf("\n%d of %d tests passed\n", total - failed_tests, total);
    return failed_tests == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
