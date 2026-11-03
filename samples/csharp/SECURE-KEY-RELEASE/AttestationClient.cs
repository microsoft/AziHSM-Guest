// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// P/Invoke wrapper around the Azure Guest Attestation Library
// (`AttestationClientLib.dll`).
//
// This library performs the AziHSM import-key attestation required for Secure
// Key Release:
//   - It collects security reports and measurements from the host environment
//     and the AziHSM device.
//   - It communicates with the Microsoft Azure Attestation (MAA) endpoint.
//   - It returns the MAA token that Azure Key Vault's key release API requires.
//
// The library ships as the NuGet package
// `Microsoft.Azure.Security.GuestAttestation`. When redistributing an
// application that uses it, remember to include `AttestationClientLib.dll`.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using AziHsm.Samples.Common.Interop;

namespace AziHsm.Samples.SecureKeyRelease;

/// <summary>
/// Managed wrapper over the Guest Attestation Library's C API.
/// </summary>
internal static unsafe partial class AttestationClient
{
    private const string AttestationDll = "AttestationClientLib";

    /// <summary>
    /// Attests the AziHSM import key against the given MAA endpoint and returns
    /// the resulting MAA token (a JWT).
    /// </summary>
    /// <param name="importKey">The AziHSM built-in import/unwrapping key.</param>
    /// <param name="maaEndpoint">
    /// The MAA endpoint URL, for example <c>https://mytenant.attest.azure.net</c>.
    /// </param>
    /// <param name="payload">
    /// A JSON object (as a string) containing AziHSM-specific claims to embed in
    /// the MAA token.
    /// </param>
    /// <param name="clientId">
    /// An optional client identifier, reported to MAA as part of the User-Agent
    /// header.
    /// </param>
    public static string AttestAziHsm(
        NCryptKeyHandle importKey,
        string maaEndpoint,
        string payload,
        string clientId = "azihsm-sample-client")
    {
        ArgumentException.ThrowIfNullOrEmpty(maaEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(payload);

        if (importKey.IsInvalid)
        {
            throw new ArgumentException("Invalid import key handle", nameof(importKey));
        }

        // Initialize the library with a logger that forwards to stdout.
        AttestationLogInfo logInfo = new()
        {
            Log = &LogCallback,
            Ctx = null,
        };

        int result = InitAttestationLib(&logInfo);
        if (result != 0)
        {
            throw new InvalidOperationException($"Failed InitAttestationLib: Error code = {result}");
        }

        try
        {
            byte* token = null;

            // `DangerousAddRef`/`DangerousRelease` keep the handle alive for the
            // duration of the native call, which may take several seconds.
            bool addedRef = false;
            try
            {
                importKey.DangerousAddRef(ref addedRef);

                result = AttestAziHsmNative(
                    maaEndpoint,
                    null,
                    payload,
                    importKey.DangerousGetHandle(),
                    &token,
                    clientId);
            }
            finally
            {
                if (addedRef)
                {
                    importKey.DangerousRelease();
                }
            }

            if (result != 0)
            {
                throw new InvalidOperationException($"Failed AttestAziHsm: Error code = {result}");
            }

            if (token is null)
            {
                throw new InvalidOperationException(
                    "Unexpected! AttestAziHsm returned success but the attestation token is null");
            }

            try
            {
                return Marshal.PtrToStringUTF8((IntPtr)token)
                    ?? throw new InvalidOperationException("Failed to read the attestation token");
            }
            finally
            {
                // The buffer was allocated by the library, so it must be freed
                // by the library.
                Free(token);
            }
        }
        finally
        {
            UninitAttestationLib();
        }
    }

    /// <summary>
    /// The logging callback that the Guest Attestation Library calls into.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void LogCallback(
        void* ctx,
        byte* logTag,
        int level,
        byte* function,
        int line,
        byte* message)
    {
        string levelName = level switch
        {
            0 => "Error",
            1 => "Warn",
            2 => "Info",
            3 => "Debug",
            _ => "Unknown",
        };

        Console.WriteLine(
            $"Level: {levelName} " +
            $"Tag: {Marshal.PtrToStringUTF8((IntPtr)logTag)} " +
            $"{Marshal.PtrToStringUTF8((IntPtr)function)}:{line}:" +
            $"{Marshal.PtrToStringUTF8((IntPtr)message)}");
    }

    [LibraryImport(AttestationDll, EntryPoint = "InitAttestationLib")]
    private static partial int InitAttestationLib(AttestationLogInfo* attestationLogInfo);

    [LibraryImport(AttestationDll, EntryPoint = "UninitAttestationLib")]
    private static partial void UninitAttestationLib();

    [LibraryImport(AttestationDll, EntryPoint = "Free")]
    private static partial void Free(void* buffer);

    // The library's entry points return a C `long`, which is 32 bits wide on
    // Windows, so they map to `int` rather than `long` in managed code.
    [LibraryImport(
        AttestationDll,
        EntryPoint = "AttestAziHsm",
        StringMarshalling = StringMarshalling.Utf8)]
    private static partial int AttestAziHsmNative(
        string attestationEndpoint,
        string? authToken,
        string aziHsmPayload,
        IntPtr aziHsmKeyHandle,
        byte** attestationToken,
        string? clientId);

    /// <summary>
    /// The logging function and context handed to the Guest Attestation
    /// Library when it is initialized.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct AttestationLogInfo
    {
        public delegate* unmanaged[Cdecl]<void*, byte*, int, byte*, int, byte*, void> Log;
        public void* Ctx;
    }
}
