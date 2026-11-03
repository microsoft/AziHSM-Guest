// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file defines the private keys used by this sample.
//
// Each key stands in for the private key that a user wants to release from an
// external service and import into the AziHSM. They are stored here as Base64
// so that the sample can run without any external infrastructure.
//
// These keys are published in a public repository and exist purely to make the
// sample self-contained. NEVER use them to protect real data.

namespace AziHsm.Samples.AttestUnwrapKey;

/// <summary>
/// Pre-generated private keys, in DER-encoded PKCS#8 form, plus the values
/// needed to check the resulting signatures.
/// </summary>
internal static class SampleKeys
{
    /// <summary>
    /// A randomly generated 2048-bit RSA private key, used to demonstrate RSA
    /// signing and verification.
    /// </summary>
    public static byte[] RsaPrivateKey => Convert.FromBase64String(RsaPrivateKeyBase64);

    /// <summary>
    /// A randomly generated NIST P-256 EC private key, used to demonstrate
    /// ECDSA signing and verification.
    /// </summary>
    public static byte[] EcdsaPrivateKey => Convert.FromBase64String(EcdsaPrivateKeyBase64);

    /// <summary>The message signed by the RSA flow.</summary>
    public const string RsaMessage = "Hello, World!";

    /// <summary>The message signed by the ECDSA flow.</summary>
    public const string EcdsaMessage = "Hello, World!";

    /// <summary>
    /// The signature produced by signing <see cref="RsaMessage"/> with
    /// <see cref="RsaPrivateKey"/> using PKCS#1 v1.5 padding over SHA-256.
    /// </summary>
    /// <remarks>
    /// RSA PKCS#1 signing is deterministic, so the sample can compare the
    /// AziHSM's output against this pre-computed value. ECDSA signatures are
    /// randomized, so no equivalent constant exists for the EC flow.
    /// </remarks>
    public static byte[] ExpectedRsaSignature => Convert.FromBase64String(ExpectedRsaSignatureBase64);

    private const string RsaPrivateKeyBase64 =
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9XdXB4JLW/mdDuIhtImVdlFPr08bhdEx3zsDYo1sbe7h1BbPjY/J9BoweQJalUIrq" +
        "pCP40sWVr8OsxLo6Cs5q4Kg2uT/LQRRBEWzFkI2yHdTZQPZvyi2ylfBAZ3rHvMNsqlxhw/CuDUe1QHnitTd+JzWynTAX0bzWQpJI8vLhxbW1mJdhaajU" +
        "+ioACY6bI4b6BycSCzyXSZThXeZxfZkoHJvs2G2GnPss3/0mOPx7txcnNOq2FS5a4DjLs5xZ7RvatE1gHPiAkJHtoIC0OZ5faJ+f4VhSe7ZxjmeNOTFB" +
        "m+ktSg6cq7on14Mvbk2AoHuaQXObgsG5Yu68N8NpPTyVAgMBAAECggEAMuY3cArcfURZXlcJ+IefxmT5n7BHS09WxHdC15glA4CgRngXb53sTlXFsNX8" +
        "iAfbpxEiiB2jNUZOqrAgPDyuWgTzwe3OK2RdPNYhrgLaS0+AaDrxYn/uA4wQzUbjNi/TOXCbLz4bAbWZGitv95NtDJAee1mL1UMvZknzhv8icLOcLbFA" +
        "4P5CI7Q9lE0Sa8cSkiGLcdbvA7V1uzLQJ4k0bHjv1FV99FuzVXp00qWdi/ULE9lZsSDwydDE0sq6Nca5wYWdmbUNx0yuVjyuOW3p12UZUzfTu2wUnJtZ" +
        "zuO9umaOHmYGg8OTVwnSCu/p6TtSD1mPD6D3tddQWyqA2fzUGwKBgQD24T24q1w764qohTOQsmJG1NhHADXTb7HTep0TyCFSTmJEEMPICjlmnYONF4Qc" +
        "td7an/tGE5kOnbecLT+YBqLh+Dg+AL/yAGJUbFIn4H7mecsiZ/g9qXGq2eebQ6x8KFZ5NbnF5DrhzVD9h4f4bVGreCJIWxJnM/RSRhYPkbUH1wKBgQDE" +
        "XK/Rz1DCtLhYusq7qg3IH9VaXvP0CK6lMPIGfLm3DfeyGKXpIVyHeILzwDlM1QP1Gg6RVezGat+4oxTDOBBfAxVOHNDsbIpTDueb4uvXkP4OMQqrBE6a" +
        "Q5aD8LQajm/JBhn3u6iRr9oErptww+mgCtEhQCIej/BXYXm721ghcwKBgQCROf6s22DufqiaaYDj5YuaTyrK2XzQXCwnU0GDmX7AhAuaLqJ80kbh7las" +
        "cODuYq4tvV564pxu1Khl3thB/eVjODkdgCNpoIA3WWEaxBziR1MPckm9PCf5cSWlWDHm93Om6cvWdWON4NF70nZR1TztuUWxeqFgxFc87q2biwMLEQKB" +
        "gQC1XPJbdAMgwvBdq7EiYe+2vog9nuPtqrM8ChgQm9SgWXtE+HUM/W5MBafV4N5Ls5ejI3z/CYDWxtF55M6BfN/KEbv02LKzG5ErI+IR3iZ8hQPSMcOr" +
        "rx+2ZeS4WnLO8G4ZGtSTNrV8UhKpLmiNX7YBxtvfvS+GUOXonzRjqTUeNwKBgEii2wL+q1saFilGZ3zgIrKyH6CUoJBmhtzprjV+rVEnBJHQEj96v+1y" +
        "2XDSO5+dGfmZGtTo0oTrqTEMa4eCMrTyF3D1OvQA6AwhKqQhImwAsdhE2xvGiRHYEiEucuuiqQ2F73tWjS3Xzr9FxHFaVlfRmk5rzYN4M2H+tgzmLtx6";

    private const string EcdsaPrivateKeyBase64 =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgR8rY4h4r5O+vBbn8K8Sia2iwzSLaKKWWwm0/7sLesYehRANCAASJgMaj4E4DFKR7IXXi" +
        "uoGR8o3dL5FNT1BnJQcU/kCghp7G7gwxcC9OSDEXLCZM2ex+zTGIb6rpmgDkkLePNjAz";

    private const string ExpectedRsaSignatureBase64 =
        "FuJNwnYLth0D8vITWRNeZ1gn+910gOwdPC0DBCaIM+Jhf47m5PTC6mfTsTzDI+tvKGLUen/ul4gGosPP6LbuyAm5W+7OmyAj/Q6LOI6tHlnYVpuiCj74" +
        "QrxcNyTqjwVC+IEDbkvsAdlpEf/t9PKZV24+keZtP7w2CJGVS0SxXUkR39b4rmSVyp4B99K/uovJHBk/fuXJY040nbnASZY+YFDcMMHEpKQUslJs7T7A" +
        "fgvqBRtpgxIJZAYsrDhgtWY1juT5I1bzpGRpsFDLW3KXzWjYOPH82TawGDHpHUNfq3uikz2y1GqE1yyIuO+Y84UwiDDvZuRTarP3t2DCeRB8HA==";
}
