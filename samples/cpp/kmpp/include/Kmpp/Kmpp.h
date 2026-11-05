// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header defines the KMPP helpers shared by the AziHSM KMPP samples (the
// C++ analog of the Rust samples' `common` crate):
//
// * a run-time loader for the three libkmpp entry points the samples need,
// * an OpenSSL library context with the `default` and `kmppprovider` providers,
// * key import / load, and the RSA operations used by the samples.
//
// Flow: import_key_der() (embedded raw key -> in-process self-signed PFX ->
// KMPP import -> opaque KeyId) -> load_provider_private_key() (KeyId ->
// provider-backed EVP_PKEY) -> rsa_oaep_encrypt() / rsa_oaep_decrypt() /
// digest_sign_sha256() / digest_verify_sha256(). Private-key operations run
// inside AziHSM; public-key operations run in OpenSSL's `default` provider.
//
// Every helper reports failure by throwing kmpp::Error, whose message carries
// the OpenSSL error queue. Nothing here prints; output is left to the samples.

#pragma once

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "The KMPP samples require OpenSSL 3.0 or later."
#endif

#include <dlfcn.h>

#include <climits>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace kmpp
{

// Single key-usage flags accepted by KMPP for AziHSM keys (keyisocert.h).
// AziHSM rejects the combined default usage, so import with exactly one.
inline constexpr int KEYISO_KEY_USAGE_SIGN_FLAG = 0x00001000;
inline constexpr int KEYISO_KEY_USAGE_ENCRYPT_FLAG = 0x00002000;

using Bytes = std::vector<unsigned char>;

// Error thrown by every helper in this header.
class Error : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

// Signature scheme selected per operation.
enum class SigScheme
{
    RsaPkcs1, // RSA PKCS#1 v1.5 (the RSA key's default padding).
    RsaPss,   // RSA-PSS with salt length == hash length (what AziHSM enforces).
};

inline const char* to_string(SigScheme scheme) noexcept
{
    return scheme == SigScheme::RsaPss ? "RSA-PSS" : "RSA PKCS#1 v1.5";
}

namespace detail
{

// std::unique_ptr deleter that calls an OpenSSL free function.
template <auto FreeFn>
struct Deleter
{
    template <typename T>
    void operator()(T* ptr) const noexcept
    {
        FreeFn(ptr);
    }
};

// OPENSSL_free is a macro, so it needs its own deleter.
struct OpenSslFree
{
    void operator()(unsigned char* ptr) const noexcept
    {
        OPENSSL_free(ptr);
    }
};

} // namespace detail

using UniquePkey = std::unique_ptr<EVP_PKEY, detail::Deleter<EVP_PKEY_free>>;

namespace detail
{

using UniqueLibCtx = std::unique_ptr<OSSL_LIB_CTX, Deleter<OSSL_LIB_CTX_free>>;
using UniqueProvider = std::unique_ptr<OSSL_PROVIDER, Deleter<OSSL_PROVIDER_unload>>;
using UniquePkeyCtx = std::unique_ptr<EVP_PKEY_CTX, Deleter<EVP_PKEY_CTX_free>>;
using UniqueMdCtx = std::unique_ptr<EVP_MD_CTX, Deleter<EVP_MD_CTX_free>>;
using UniqueX509 = std::unique_ptr<X509, Deleter<X509_free>>;
using UniqueX509Name = std::unique_ptr<X509_NAME, Deleter<X509_NAME_free>>;
using UniquePkcs12 = std::unique_ptr<PKCS12, Deleter<PKCS12_free>>;
using UniqueDer = std::unique_ptr<unsigned char, OpenSslFree>;

// The throwaway PKCS#12 that carries an embedded key into KMPP.
inline constexpr char kPfxPassword[] = "sample";
inline constexpr char kPfxFriendlyName[] = "kmpp-sample";
inline constexpr char kCertCommonName[] = "KMPP Sample";
inline constexpr int kCertValidityDays = 3650;

// libkmpp sonames tried in order: installed runtime soname, then devel symlink.
inline constexpr const char* kKmppSonames[] = {"libkmpp.so.1", "libkmpp.so"};

// Throws kmpp::Error with `what` followed by the drained OpenSSL error queue.
[[noreturn]] inline void throw_openssl_error(const std::string& what)
{
    std::string message = what;
    char line[256];
    for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error())
    {
        ERR_error_string_n(code, line, sizeof(line));
        message += "\n  ";
        message += line;
    }
    throw Error(message);
}

inline void check(bool ok, const char* what)
{
    if (!ok)
    {
        throw_openssl_error(what);
    }
}

// Validates a caller-supplied argument (no OpenSSL involved).
inline void require(bool ok, const char* what)
{
    if (!ok)
    {
        throw Error(std::string("invalid argument: ") + what);
    }
}

// KMPP client C ABI (kmppclient/include/keyisopfxclient.h, keyisoclientprov.h,
// include/keyisomemory.h).
using ImportPfxToKeyIdFn = int (*)(const unsigned char* correlation_id, // uuid_t; NULL is accepted.
                                   int keyiso_flags,
                                   int in_pfx_length,
                                   const unsigned char* in_pfx_bytes,
                                   const char* password,
                                   int* verify_chain_error,
                                   char** key_id);
using LoadProviderPrivateKeyFn = EVP_PKEY* (*)(OSSL_LIB_CTX* libctx, const char* provider_key_id);
using ClearFreeStringFn = void (*)(char* str);

struct KmppApi
{
    ImportPfxToKeyIdFn import_pfx_to_key_id;
    LoadProviderPrivateKeyFn load_provider_private_key;
    ClearFreeStringFn clear_free_string;
};

// Resolves one libkmpp symbol. A null symbol can be a valid value, so dlerror()
// is the only reliable failure signal; it is cleared first.
template <typename Fn>
Fn resolve_symbol(void* handle, const char* name)
{
    dlerror();
    void* symbol = dlsym(handle, name);
    if (const char* error = dlerror())
    {
        throw Error(std::string("libkmpp is missing symbol '") + name + "': " + error);
    }
    // POSIX guarantees an object pointer from dlsym() converts to a function pointer.
    Fn fn = nullptr;
    static_assert(sizeof(fn) == sizeof(symbol));
    std::memcpy(&fn, &symbol, sizeof(fn));
    return fn;
}

inline KmppApi load_kmpp_api()
{
    // RTLD_NOW resolves everything up front. RTLD_GLOBAL is required: kmppprovider
    // and the AziHSM backend resolve KeyIso_* helpers from global scope.
    void* handle = nullptr;
    for (const char* soname : kKmppSonames)
    {
        handle = dlopen(soname, RTLD_NOW | RTLD_GLOBAL);
        if (handle != nullptr)
        {
            break;
        }
    }
    if (handle == nullptr)
    {
        throw Error("could not load libkmpp (libkmpp.so.1, libkmpp.so). Install the KMPP client "
                    "package and make sure it is on the loader search path (a system library "
                    "directory or LD_LIBRARY_PATH).");
    }

    // The handle is never closed: kmppprovider uses these symbols for the process lifetime.
    return KmppApi{
        resolve_symbol<ImportPfxToKeyIdFn>(handle, "KeyIso_import_pfx_to_key_id"),
        resolve_symbol<LoadProviderPrivateKeyFn>(handle, "KeyIso_load_provider_private_key"),
        resolve_symbol<ClearFreeStringFn>(handle, "KeyIso_clear_free_string"),
    };
}

// Loads libkmpp once per process (thread-safe; retried on the next call if it throws).
inline const KmppApi& kmpp_api()
{
    static const KmppApi api = load_kmpp_api();
    return api;
}

// Builds a PKCS#12 (PFX, DER) from a raw private key (DER; PKCS#1 or PKCS#8) by
// minting a self-signed certificate over it. The PFX is protected with kPfxPassword.
inline Bytes build_self_signed_pfx(const unsigned char* key_der, std::size_t key_der_len)
{
    require(key_der != nullptr && key_der_len > 0, "the private key DER must not be empty");
    if (key_der_len > static_cast<std::size_t>(LONG_MAX))
    {
        throw Error("embedded key is too large");
    }
    const unsigned char* cursor = key_der;
    UniquePkey pkey(d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(key_der_len)));
    check(pkey != nullptr, "decoding the embedded private key (DER) failed");

    UniqueX509Name name(X509_NAME_new());
    check(name != nullptr &&
              X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                         reinterpret_cast<const unsigned char*>(kCertCommonName),
                                         -1, -1, 0) == 1,
          "building the certificate name failed");

    UniqueX509 cert(X509_new());
    check(cert != nullptr &&
              X509_set_version(cert.get(), X509_VERSION_3) == 1 &&
              ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1 &&
              X509_set_subject_name(cert.get(), name.get()) == 1 &&
              X509_set_issuer_name(cert.get(), name.get()) == 1 && // self-signed: issuer == subject
              X509_set_pubkey(cert.get(), pkey.get()) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) != nullptr &&
              X509_time_adj_ex(X509_getm_notAfter(cert.get()), kCertValidityDays, 0, nullptr) != nullptr &&
              X509_sign(cert.get(), pkey.get(), EVP_sha256()) > 0,
          "building the self-signed certificate failed");

    UniquePkcs12 p12(PKCS12_create(kPfxPassword, kPfxFriendlyName, pkey.get(), cert.get(),
                                   nullptr, 0, 0, 0, 0, 0));
    check(p12 != nullptr, "building the PKCS#12 failed");

    unsigned char* der = nullptr;
    const int der_len = i2d_PKCS12(p12.get(), &der);
    UniqueDer owned_der(der);
    check(der_len > 0, "encoding the PKCS#12 failed");
    return Bytes(der, der + der_len);
}

inline Bytes rsa_oaep(EVP_PKEY* pkey, bool encrypt, const Bytes& input)
{
    require(pkey != nullptr, "the RSA key must not be null");
    require(!input.empty(), encrypt ? "the plaintext must not be empty" : "the ciphertext must not be empty");

    UniquePkeyCtx ctx(EVP_PKEY_CTX_new(pkey, nullptr));
    check(ctx != nullptr, "EVP_PKEY_CTX_new failed");
    check((encrypt ? EVP_PKEY_encrypt_init(ctx.get()) : EVP_PKEY_decrypt_init(ctx.get())) > 0,
          "RSA operation init failed");
    // The OAEP hash stays at the OpenSSL default (SHA-1): KMPP does not carry the
    // OAEP digest to its backends, so decrypt always uses SHA-1.
    check(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) > 0,
          "setting OAEP padding failed");

    const auto run = [&](unsigned char* out, std::size_t* out_len) {
        return encrypt ? EVP_PKEY_encrypt(ctx.get(), out, out_len, input.data(), input.size())
                       : EVP_PKEY_decrypt(ctx.get(), out, out_len, input.data(), input.size());
    };
    std::size_t len = 0;
    check(run(nullptr, &len) > 0, "RSA-OAEP size query failed");
    Bytes output(len);
    check(run(output.data(), &len) > 0, encrypt ? "RSA-OAEP encrypt failed" : "RSA-OAEP decrypt failed");
    output.resize(len);
    return output;
}

inline void apply_scheme(EVP_PKEY_CTX* pctx, SigScheme scheme)
{
    if (scheme != SigScheme::RsaPss)
    {
        return; // PKCS#1 v1.5 is the RSA key's default padding.
    }
    check(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0, "setting PSS padding failed");
    check(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0,
          "setting the PSS salt length failed");
}

} // namespace detail

// Opaque KMPP KeyID. Owns the string returned by KeyIso_import_pfx_to_key_id and
// releases it with KeyIso_clear_free_string.
class KeyId
{
public:
    explicit KeyId(char* id) noexcept : id_(id) {}
    KeyId(KeyId&& other) noexcept : id_(std::exchange(other.id_, nullptr)) {}
    KeyId(const KeyId&) = delete;
    KeyId& operator=(const KeyId&) = delete;
    KeyId& operator=(KeyId&&) = delete;

    ~KeyId()
    {
        if (id_ != nullptr)
        {
            detail::kmpp_api().clear_free_string(id_);
        }
    }

    const char* get() const noexcept { return id_; }

private:
    char* id_;
};

// An OSSL_LIB_CTX with the `default` and `kmppprovider` providers loaded.
class ProviderContext
{
public:
    ProviderContext()
    {
        detail::kmpp_api(); // Report a missing libkmpp before touching OpenSSL.

        lib_ctx_.reset(OSSL_LIB_CTX_new());
        detail::check(lib_ctx_ != nullptr, "OSSL_LIB_CTX_new failed");
        default_provider_.reset(OSSL_PROVIDER_load(lib_ctx_.get(), "default"));
        detail::check(default_provider_ != nullptr, "failed to load the OpenSSL 'default' provider");
        kmpp_provider_.reset(OSSL_PROVIDER_load(lib_ctx_.get(), "kmppprovider"));
        detail::check(kmpp_provider_ != nullptr,
                      "failed to load 'kmppprovider' (install the KMPP OpenSSL provider, or set "
                      "OPENSSL_MODULES to the directory that holds kmppprovider.so)");
    }

    OSSL_LIB_CTX* get() const noexcept { return lib_ctx_.get(); }

private:
    // Members are destroyed in reverse order, so both providers are unloaded
    // before the library context they belong to is freed.
    detail::UniqueLibCtx lib_ctx_;
    detail::UniqueProvider default_provider_;
    detail::UniqueProvider kmpp_provider_;
};

// Imports a raw private key (unencrypted DER: PKCS#1 or PKCS#8) into KMPP with
// exactly one usage flag: the key is wrapped in a throwaway self-signed PFX (the
// KMPP analog of the KSP samples' wrap_rsa_key) and imported, which materializes
// it inside AziHSM. Only the opaque KeyID comes back.
//
// `import_status` (optional) receives the KMPP return value: 1 = imported and
// the certificate chain validated, -1 = imported with a chain warning (expected
// for the self-signed certificate; the KeyID is fully usable).
inline KeyId import_key_der(int usage_flag, const unsigned char* key_der, std::size_t key_der_len,
                            int* import_status = nullptr)
{
    detail::require(usage_flag == KEYISO_KEY_USAGE_SIGN_FLAG || usage_flag == KEYISO_KEY_USAGE_ENCRYPT_FLAG,
                    "the usage flag must be exactly one of the SIGN / ENCRYPT flags");
    const detail::KmppApi& api = detail::kmpp_api();
    Bytes pfx = detail::build_self_signed_pfx(key_der, key_der_len);
    if (pfx.size() > static_cast<std::size_t>(INT_MAX))
    {
        throw Error("PFX is too large for the KMPP API");
    }

    int verify_chain_error = 0;
    char* raw_key_id = nullptr;
    const int ret = api.import_pfx_to_key_id(nullptr, usage_flag, static_cast<int>(pfx.size()),
                                             pfx.data(), detail::kPfxPassword,
                                             &verify_chain_error, &raw_key_id);
    OPENSSL_cleanse(pfx.data(), pfx.size());
    KeyId key_id(raw_key_id);

    if (ret == 0 || raw_key_id == nullptr)
    {
        throw Error("KeyIso_import_pfx_to_key_id failed (ret=" + std::to_string(ret) +
                    ", verifyChainError=" + std::to_string(verify_chain_error) + ")");
    }
    if (import_status != nullptr)
    {
        *import_status = ret;
    }
    return key_id;
}

// Loads a KeyID through kmppprovider into a provider-backed private key.
inline UniquePkey load_provider_private_key(const ProviderContext& context, const KeyId& key_id)
{
    detail::require(key_id.get() != nullptr, "the KeyID must not be empty");
    UniquePkey pkey(detail::kmpp_api().load_provider_private_key(context.get(), key_id.get()));
    detail::check(pkey != nullptr, "KeyIso_load_provider_private_key failed");
    return pkey;
}

// Derives a plain public key (default provider) from any key, for independent
// signature verification.
inline UniquePkey public_from_key(EVP_PKEY* pkey)
{
    detail::require(pkey != nullptr, "the key must not be null");
    unsigned char* der = nullptr;
    const int der_len = i2d_PUBKEY(pkey, &der);
    detail::UniqueDer owned_der(der);
    detail::check(der_len > 0, "exporting the public key failed");

    const unsigned char* cursor = der;
    UniquePkey public_key(d2i_PUBKEY(nullptr, &cursor, der_len));
    detail::check(public_key != nullptr, "importing the public key failed");
    return public_key;
}

// RSA-OAEP encrypt with `public_key` (in process, no HSM call). Pass a plain public
// key (see public_from_key) so the encrypt runs in OpenSSL's default provider.
inline Bytes rsa_oaep_encrypt(EVP_PKEY* public_key, const Bytes& plaintext)
{
    return detail::rsa_oaep(public_key, true, plaintext);
}

// RSA-OAEP decrypt with the private key; for a provider-backed key this runs in AziHSM.
inline Bytes rsa_oaep_decrypt(EVP_PKEY* pkey, const Bytes& ciphertext)
{
    return detail::rsa_oaep(pkey, false, ciphertext);
}

// Signs SHA-256(`message`) with `scheme`; for a provider-backed key this runs in
// AziHSM. No property query is passed: the key is already anchored to
// kmppprovider, and a mandatory `provider=` query would also force the SHA-256
// fetch into KMPP, which has no digests.
inline Bytes digest_sign_sha256(EVP_PKEY* pkey, const Bytes& message, SigScheme scheme)
{
    detail::require(pkey != nullptr, "the signing key must not be null");
    detail::UniqueMdCtx md_ctx(EVP_MD_CTX_new());
    detail::check(md_ctx != nullptr, "EVP_MD_CTX_new failed");
    EVP_PKEY_CTX* pctx = nullptr; // Owned by md_ctx.
    detail::check(EVP_DigestSignInit(md_ctx.get(), &pctx, EVP_sha256(), nullptr, pkey) > 0,
                  "EVP_DigestSignInit failed");
    detail::apply_scheme(pctx, scheme);
    detail::check(EVP_DigestSignUpdate(md_ctx.get(), message.data(), message.size()) > 0,
                  "EVP_DigestSignUpdate failed");

    std::size_t len = 0;
    detail::check(EVP_DigestSignFinal(md_ctx.get(), nullptr, &len) > 0, "signature size query failed");
    Bytes signature(len);
    detail::check(EVP_DigestSignFinal(md_ctx.get(), signature.data(), &len) > 0, "signing failed");
    signature.resize(len);
    return signature;
}

// Verifies `signature` over SHA-256(`message`) with a public key, independently
// of KMPP. Returns false if the signature does not match; throws on errors.
inline bool digest_verify_sha256(EVP_PKEY* public_key, const Bytes& message, const Bytes& signature,
                                 SigScheme scheme)
{
    detail::require(public_key != nullptr, "the verification key must not be null");
    detail::require(!signature.empty(), "the signature must not be empty");
    detail::UniqueMdCtx md_ctx(EVP_MD_CTX_new());
    detail::check(md_ctx != nullptr, "EVP_MD_CTX_new failed");
    EVP_PKEY_CTX* pctx = nullptr; // Owned by md_ctx.
    detail::check(EVP_DigestVerifyInit(md_ctx.get(), &pctx, EVP_sha256(), nullptr, public_key) > 0,
                  "EVP_DigestVerifyInit failed");
    detail::apply_scheme(pctx, scheme);
    detail::check(EVP_DigestVerifyUpdate(md_ctx.get(), message.data(), message.size()) > 0,
                  "EVP_DigestVerifyUpdate failed");

    const int result = EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size());
    if (result == 1)
    {
        return true;
    }
    if (result == 0)
    {
        ERR_clear_error(); // A mismatch is a result, not an error.
        return false;
    }
    detail::throw_openssl_error("signature verification failed");
}

} // namespace kmpp
