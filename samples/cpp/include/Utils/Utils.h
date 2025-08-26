// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header file defines general helper functions that are used by several
// of the AziHSM samples.

#pragma once

// Use `WIN32_NO_STATUS` to prevent macro-redefinition warnings in `ntstatus.h`
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>

// Helper function that creates a heap-allocated string representing a provided
// buffer as a string of hexadecimal values.
static HRESULT buffer_to_hex(BYTE* buffer, size_t buffer_len, char** result, size_t* result_len)
{
    HRESULT status = S_OK;
    size_t str_idx = 0;

    // Allocate a buffer of an appropriate length. On failure to allocate,
    // return early with an error
    size_t str_len = (buffer_len * 3);
    char* str = (char*)malloc(sizeof(char) * (str_len + 1));
    if (str == NULL)
    {
        status = E_OUTOFMEMORY;
        goto buffer_to_hex_cleanup;
    }

    // For each byte in the buffer, append a hex string to the buffer
    for (size_t i = 0; i < buffer_len; i++)
    {
        int ret = snprintf(str + str_idx, str_len - str_idx, "%02x%s", buffer[i], i < buffer_len - 1 ? " " : "");
        if (ret < 0)
        {
            // Enough memory is allocated for `snprintf()` to succeed every
            // time it's called in this loop; a failure here is unexpected`
            status = E_UNEXPECTED;
            goto buffer_to_hex_cleanup;
        }

        str_idx += (size_t)ret;
    }
    str[str_idx] = '\0';

    // On success, set the return pointers and return value. Set `str` to NULL
    // to move ownership off the buffer to `*result`.
    *result = str;
    *result_len = str_idx;
    str = NULL;
    status = S_OK;

    // Cleanup routine: on failure, resources are freed.
buffer_to_hex_cleanup:
    HRESULT exit_status = status;
    // If `str` was not reset to NULL, then something went wrong above, and we
    // should free the buffer before returning.
    if (str != NULL)
    {
        free(str);
    }
    return exit_status;
}

// Helper function that fills the provided buffer with random bytes.
static NTSTATUS randomize_buffer(BYTE* buffer, size_t buffer_len)
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
