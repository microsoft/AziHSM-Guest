// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines error handling helpers used by the AziHSM samples.
//
// AziHSM exposes its functions via the NCrypt API, and reports errors by
// returning an existing `SECURITY_STATUS` (`HRESULT`) error code. Every NCrypt
// function returns one, and a negative value indicates failure.
//
// You could look up the error code and have a general idea about what went
// wrong. For more detailed logging from AziHSM, which includes more details
// about why an error was thrown, see `docs/EventTracing.md`.

using System.ComponentModel;

namespace AziHsm.Samples.Common.Interop;

/// <summary>
/// The exception thrown when an NCrypt call against the AziHSM KSP fails.
/// </summary>
public sealed class NCryptException : Exception
{
    public NCryptException(int status, string message)
        : base($"{message}. NCrypt returned 0x{status:X8}: {DescribeStatus(status)}")
    {
        HResult = status;
        Status = status;
    }

    /// <summary>The <c>SECURITY_STATUS</c> (<c>HRESULT</c>) returned by NCrypt.</summary>
    public int Status { get; }

    private static string DescribeStatus(int status) => new Win32Exception(status).Message;
}

/// <summary>
/// Helpers for inspecting <c>SECURITY_STATUS</c> values returned by NCrypt.
/// </summary>
public static class NCryptStatus
{
    /// <summary><c>S_OK</c>.</summary>
    public const int Success = 0;

    /// <summary>Returns <c>true</c> when the status code indicates success.</summary>
    public static bool Succeeded(int status) => status >= 0;

    /// <summary>Returns <c>true</c> when the status code indicates failure.</summary>
    public static bool Failed(int status) => status < 0;

    /// <summary>
    /// Throws an <see cref="NCryptException"/> when <paramref name="status"/>
    /// indicates failure.
    /// </summary>
    /// <remarks>
    /// The samples call this after every NCrypt invocation. The
    /// <paramref name="message"/> should name the call that failed, so that the
    /// resulting exception identifies both the operation and the status code.
    /// </remarks>
    public static void ThrowIfFailed(int status, string message)
    {
        if (Failed(status))
        {
            throw new NCryptException(status, message);
        }
    }
}
