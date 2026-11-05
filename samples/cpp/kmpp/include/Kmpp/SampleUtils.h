// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header defines the helpers every KMPP sample shares: the sample message,
// hex printing, the common "import + load the key" step, and a `main` wrapper
// that handles `--help` and turns exceptions into a failing exit code.

#pragma once

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string_view>
#include <utility>

#include "Kmpp/Kmpp.h"
#include "Kmpp/RsaKeys.h"

namespace kmpp::sample
{

// Message signed / encrypted by every sample (same as the Rust samples).
inline constexpr std::string_view kMessage = "KMPP x AziHSM: hello from the HSM";

inline constexpr std::size_t kHexBytesPerLine = 32;

inline Bytes message_bytes()
{
    return Bytes(kMessage.begin(), kMessage.end());
}

// Prints "  <label> (<n> bytes):" followed by `data` as wrapped uppercase hex.
inline void print_hex(const char* label, const Bytes& data)
{
    std::printf("  %s (%zu bytes):\n    ", label, data.size());
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        std::printf("%02X", data[i]);
        if ((i + 1) % kHexBytesPerLine == 0 && i + 1 != data.size())
        {
            std::printf("\n    ");
        }
    }
    std::printf("\n");
}

// An imported key ready for use. Members are destroyed in reverse order: the
// EVP_PKEY first, then the KeyID, then the provider context it was loaded into.
struct LoadedKey
{
    ProviderContext context;
    KeyId key_id;
    UniquePkey pkey;
};

// Step 1 of every sample: import the embedded key into KMPP with a single usage
// flag (the private key is materialized inside AziHSM) and load it back through
// kmppprovider as an EVP_PKEY.
inline LoadedKey import_and_load(const TestKey& key, int usage_flag, const char* usage_name)
{
    ProviderContext context;

    std::printf("[step 1] import + load embedded %s test key (%s usage)\n", key.name, usage_name);
    int import_status = 0;
    KeyId key_id = import_key_der(usage_flag, key.der, key.size, &import_status);
    std::printf("  imported PFX -> KeyID (isolated in AziHSM); import ret=%d\n", import_status);

    UniquePkey pkey = load_provider_private_key(context, key_id);
    std::printf("  loaded KeyID via KMPP provider -> EVP_PKEY (%d bits)\n", EVP_PKEY_get_bits(pkey.get()));

    return LoadedKey{std::move(context), std::move(key_id), std::move(pkey)};
}

// Shared `main` for the samples: prints `usage` for -h/--help, otherwise prints
// the banner and runs `body` with the optional first argument. Returns
// EXIT_SUCCESS, or EXIT_FAILURE after printing the error.
template <typename Body>
int run_sample(int argc, char** argv, const char* usage, const char* banner, Body&& body)
{
    // Line-buffer stdout so progress and errors (stderr) stay in order when piped.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    const char* arg = argc > 1 ? argv[1] : nullptr;
    if (arg != nullptr && (std::strcmp(arg, "-h") == 0 || std::strcmp(arg, "--help") == 0))
    {
        std::printf("%s\n", usage);
        return EXIT_SUCCESS;
    }

    std::printf("=== %s ===\n", banner);
    try
    {
        std::forward<Body>(body)(arg);
        return EXIT_SUCCESS;
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "error: %s\n", ex.what());
    }
    catch (...)
    {
        std::fprintf(stderr, "error: unknown exception\n");
    }
    return EXIT_FAILURE;
}

} // namespace kmpp::sample
