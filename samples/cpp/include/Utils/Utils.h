// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header file defines general helper functions that are used by several
// of the AziHSM samples.

#pragma once

#include <windows.h>
#include <winerror.h>

#include <strsafe.h>

#include <wil/result.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>

static const size_t MAX_WIDE_STRING_BYTES = 1024;

// Helper function that counts the number of bytes in a wide string (including
// the null terminator).
inline HRESULT count_wide_string_bytes(const wchar_t* str, size_t* result)
{
    size_t byte_count = 0;
    HRESULT r = StringCbLengthW(str, MAX_WIDE_STRING_BYTES, &byte_count);
    if (SUCCEEDED(r))
    {
        // Add the size of the null terminator to the result, since
        // `StringCbLengthW()` does not include it in its count.
        byte_count += sizeof(wchar_t);
        *result = byte_count;
    }
    return r;
}

// Helper function that counts the number of characters in the given wide
// string (not including the null terminator).
inline HRESULT get_wide_string_len(const wchar_t* str, size_t* result)
{
    size_t len = 0;
    HRESULT r = StringCbLengthW(str, MAX_WIDE_STRING_BYTES, &len);
    if (SUCCEEDED(r))
    {
        *result = len / sizeof(wchar_t);
    }
    return r;
}

inline void set_wil_log_callback() {
    wil::SetResultLoggingCallback([](wil::FailureInfo const& failure) noexcept
        {
            constexpr std::size_t sizeOfLogMessageWithNul = 2048;

            wchar_t logMessage[sizeOfLogMessageWithNul];
            if (SUCCEEDED(wil::GetFailureLogString(logMessage, sizeOfLogMessageWithNul, failure)))
            {
                std::fputws(logMessage, stderr);
            }
        });
}

// Helper function that creates a heap-allocated string representing a provided
// buffer as a string of hexadecimal values.
inline std::string buffer_to_hex(const BYTE* buffer, size_t buffer_len)
{
    if (buffer_len == 0) {
        return "<empty>";
    }

    std::stringstream ss;
    // Set stream to hex mode, uppercase, and pad with '0'
    ss << std::hex << std::setfill('0') << std::uppercase;
    for (size_t i = 0; i < buffer_len; ++i) {
        // Cast to int to ensure it's treated as a number, not a character
        ss << std::setw(2) << static_cast<int>(buffer[i]);
    }
    return ss.str();
}

// Helper function that fills the provided buffer with random bytes.
inline NTSTATUS randomize_buffer(BYTE* buffer, size_t buffer_len)
{
    NTSTATUS status = STATUS_SUCCESS;

    // Initialize a BCrypt Algorithm Provider to use for generating random
    // numbers. On failure to open the algorithm provider, return early.
    BCRYPT_ALG_HANDLE alg = 0;
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr,
            "Failed to open BCrypt Algorithm Provider. "
            "BCryptOpenAlgorithmProvider returned: 0x%08x\n",
            status);
        goto randomize_buffer_cleanup;
    }

    // Invoke `BCryptGenRandom ()` to fill the buffer with random bytes.
    status = BCryptGenRandom(alg, (PUCHAR)buffer, (ULONG)buffer_len * sizeof(BYTE), 0);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        fprintf(stderr,
            "Failed to generate random bytes with BCrypt. "
            "BCryptGenRandom returned: 0x%08x\n",
            status);
        goto randomize_buffer_cleanup;
    }

    // Cleanup label for closing the algorithm provider and returning the
    // appropriate status.
    status = STATUS_SUCCESS;
randomize_buffer_cleanup:
    NTSTATUS exit_status = status;

    // Close the algorithm provider, if applicable.
    if (alg != 0)
    {
        status = BCryptCloseAlgorithmProvider(alg, 0);
        if (FAILED(HRESULT_FROM_NT(status)))
        {
            fprintf(stderr,
                "Failed to close BCrypt Algorithm Provider. "
                "BCryptCloseAlgorithmProvider returned: 0x%08x\n",
                status);
        }
    }

    return exit_status;
}

// Generates and returns a random unsigned integer.
inline NTSTATUS random_uint(size_t* result)
{
    // Fill a temporary buffer with random bytes.
    size_t buffer_len = sizeof(size_t);
    BYTE buffer[sizeof(size_t)];
    NTSTATUS status = randomize_buffer(buffer, buffer_len);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        return status;
    }

    // Copy the random bytes into the result variable.
    *result = *((size_t*)buffer);
    return STATUS_SUCCESS;
}

// Generates and returns a random unsigned integer in the specified range.
inline NTSTATUS random_uint_range(size_t* result, size_t min, size_t max)
{
    // Make sure the provided range is valid.
    if (min >= max)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // Generate a random `size_t` value.
    size_t rand_value;
    NTSTATUS status = random_uint(&rand_value);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        return status;
    }

    // Scale the random integer to the specified range, and return it.
    size_t range = max - min;
    *result = (rand_value % range) + min;
    return STATUS_SUCCESS;
}

// Generates and returns a random unsighed integer in the specified range,
// while maintaining the result's alignment as a multiple of the provided
// `multiple` integer.
inline NTSTATUS random_uint_range_multiple(size_t* result, size_t min, size_t max, size_t multiple)
{
    // Make sure the provided range and multiple are valid.
    if (min >= max || multiple == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // Generate a random integer in the specified range.
    size_t rand_value;
    NTSTATUS status = random_uint_range(&rand_value, min, max);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        return status;
    }

    // Round the random integer down to the nearest multiple of `multiple`
    // (that's within the range), and return it.
    *result = (((rand_value - min) / multiple) * multiple) + min;
    return STATUS_SUCCESS;
}

// ============================== Status Codes ============================== //
enum class AZIHSM_STATUS
{
    AZIHSM_SUCCESS = 0,
    AZIHSM_FAILURE = 1,  // generic failure
    AZIHSM_CLAIM_BUFFER_INVALID_FORMAT = 2,
    AZIHSM_CLAIM_BUFFER_INVALID_LENGTH = 3,
    AZIHSM_CLAIM_BUFFER_VERSION_UNSUPPORTED = 4,
};

struct AziHSMClaimHeader {
    UINT32 Version;
    UINT32 TotalLength;
    UINT32 QuoteLength;
    UINT32 CertificateLength;
};

// Parse the claim buffer obtained from NCryptCreateClaim
// Buffer format (all numbers are in little-endian):
// - Header
// - 4 bytes: UINT32, version, currently 1
// - 4 bytes: UINT32, buffer total length, including header
// - 4 bytes: UINT32, length of attestation report in bytes
// - 4 bytes: UINT32, length of certificate in bytes
// - payload
// - N bytes: attestation report
// - M bytes: certificate
//
// Outputs: the offsets and sizes of quote and certificate within the claim buffer
inline AZIHSM_STATUS azihsm_parse_claim(
    PBYTE bufferClaim,
    DWORD bufferClaimSize,
    DWORD* outBufferQuoteOffset,
    DWORD* outBufferQuoteSize,
    DWORD* outBufferCertificateOffset,
    DWORD* outBufferCertificateSize) {
    DWORD headerSize = (DWORD)sizeof(AziHSMClaimHeader);

    if (bufferClaimSize < headerSize)
    {
        return AZIHSM_STATUS::AZIHSM_CLAIM_BUFFER_INVALID_FORMAT;
    }

    AziHSMClaimHeader header = *(AziHSMClaimHeader*)bufferClaim;
    if (header.Version != 1)
    {
        return AZIHSM_STATUS::AZIHSM_CLAIM_BUFFER_VERSION_UNSUPPORTED;
    }

    // Verify lengths
    if ((headerSize + header.QuoteLength + header.CertificateLength) != header.TotalLength ||
        header.TotalLength != bufferClaimSize)
    {
        return AZIHSM_STATUS::AZIHSM_CLAIM_BUFFER_INVALID_LENGTH;
    }

    // Return offsets for quote and certificate
    *outBufferQuoteOffset = headerSize;
    *outBufferQuoteSize = header.QuoteLength;

    *outBufferCertificateOffset = headerSize + header.QuoteLength;
    *outBufferCertificateSize = header.CertificateLength;

    return AZIHSM_STATUS::AZIHSM_SUCCESS;
}
