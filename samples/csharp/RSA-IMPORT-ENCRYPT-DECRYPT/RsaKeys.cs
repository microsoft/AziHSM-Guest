// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines the RSA keys used by this sample.
//
// The sample uses these to represent external, "bring your own key" private
// keys that can be imported into the AziHSM and then used for crypto
// operations. Each key is a randomly generated RSA private key in DER-encoded
// PKCS#8 form, stored here as Base64 for compactness.
//
// These keys are published in a public repository and exist purely to make the
// sample self-contained. NEVER use them to protect real data.

namespace AziHsm.Samples.RsaImport;

/// <summary>The RSA key lengths this sample can import.</summary>
internal enum RsaKeyLength
{
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

/// <summary>
/// Pre-generated RSA private keys, in DER-encoded PKCS#8 form.
/// </summary>
internal static class RsaKeys
{
    /// <summary>
    /// Returns the DER-encoded PKCS#8 private key for the requested key length.
    /// </summary>
    public static byte[] Get(RsaKeyLength keyLength) => Convert.FromBase64String(keyLength switch
    {
        RsaKeyLength.Rsa2048 => Rsa2048PrivateKeyBase64,
        RsaKeyLength.Rsa3072 => Rsa3072PrivateKeyBase64,
        RsaKeyLength.Rsa4096 => Rsa4096PrivateKeyBase64,
        _ => throw new ArgumentOutOfRangeException(nameof(keyLength), keyLength, "Unknown RSA key length"),
    });

    // ================================ RSA 2048 ================================ //
    private const string Rsa2048PrivateKeyBase64 =
        "MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQDhYHfiYj+EVskqwfIJnpciiGhHpJQ1boGFxuYeqFm4aW/+KTGWrGiKCTk7iZuWv48j" +
        "EmG/RmltZyhWq99ByV6AC3OsvlAI4CkScc7Qjv8+kD1azBR/qfBo3BzYr2TMC0OxqT376LyQGkXS2xf1erWznmQxpUO3lKcxKXlBaRTdbWdoCjY4DjXG" +
        "Ys84zFJkjaZ+fnBgRiloPEIu4tghbQFlxYY26w8ebfHYe+BNznHINVxvDEqL+Acja/5H3L0C8v+w388C9qFLa5nMxnYwxeQC9KICv3ExPYBwYCMSrS8C" +
        "IEJnFXpt9Fgqih0lHf0BP4NfWvsRmNpVlo8mYSWL2/zJAgMBAAECgf97i2YsXa8ehx8UppGyCZLPsKF5TxPvi6QfW+jJkCpJQi3M0B1e0HkohzstvUE3" +
        "tx+/xKkl28iZ2vKXOvV8xTtdoD7IyDUXUx8wp90MdqwfSketKNy+dBRVZv5pHxHMyF/+A8hL+Z4Ota2Q6Ik5sl/oa+srS8Ioiv8bnqCEOsDf9RFupZPT" +
        "BRNrmHAdqI3aLc3LEUhZ9KqpirCK9I20ADWfK0SZBkGZy+Qkwfq0K0LHvlDRyhbtaWj+zBPQa4yi/Zc39NwrWWPwTxUebUrtFk//yHN5j0w/KfoAjcHy" +
        "6TJGrmidZOG+Dj2tMaQfFlhzXYlw2dv0kattcfArjflZ1x0CgYEA+5wr3rLaDccW1Gm3yrEtPUvQSpy7xpl9/lCy3oRk7734cp5VTramoWhHsGl3Gntj" +
        "SgXB+s4QnB8YGka5tWbv/AQpJ7k9pIV4meRuLrBCu5WTRvlwkRvzmvuqlnyCdzO5mC+j1CSCyld03hk4PsLaMQP5bct/XJDIDWIxq7PehJsCgYEA5U8f" +
        "/xkXwkD15DqIqqVFERPnKxSWg7uDP3UHqpQdgtaKY63xOrRMzTQJZcbiC/3DTZV88p1el+FKB1+yewpOAECxpTv2mSG1i5fB8R6G+qoDf6iasQGYifEB" +
        "Y4lk1AtuiXLJhc9VnOguNL3zfDLC/PjF8fWpEsDy7rSxV1sQsGsCgYB00r03yHkgHolGFNPmQ7+Kj1Hl4sH44zmxxAxY7sXi3qSlq0hWpM3XcZCfo0hO" +
        "vm2KaAP6DIV/x5wsTxxY0rOootHtBMBPTD2DzqEuAl7ps/hO4vBWH9FK64D4IFV/PT/2HmCF1nH3uwWjPbh0w4oFah/8z5iSBRMty6LeY0R08wKBgGwL" +
        "/GeWyzscoMAJVJwTg5eoaSRDbyhjElS0MAiQAdfEfzC4pRGkIwwNmN/79kbwKzZDWbx3qjqmTNtsnAydrmMwGIRi3K8K0yATQa77U16I/V0JdNoyhk14" +
        "4c6kzn2bZVoeXBZQu2ZTgHIZjsDWqknIbnyz5BaSE+Wl/mnK3vJBAoGAJPABDzTHJyt68U4EUNMYK5x1ECIcqmO5elLTFZGm9NSkJ1EXEAGsg/eVWPRw" +
        "KTdlYw9ed3XTRIOh8E6bZv1LOGUrXZ9NPC62yeMQP9QULm8g5XcfkkHCYCNKmL0rJDwjAqkyXiHnvi5WkKtJc0l8+dmMb0axEzJcXgfqdAJFzoc=";

    // ================================ RSA 3072 ================================ //
    private const string Rsa3072PrivateKeyBase64 =
        "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";

    // ================================ RSA 4096 ================================ //
    private const string Rsa4096PrivateKeyBase64 =
        "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" +
        "geLrPbzGVfKerq/wmOLBtqEFduiRQz77cis=";
}
