# Samples

Sample applications that demonstrate usage of AziHSM. The same set of scenarios is implemented in each supported language, so you can compare them side by side.

| Language | Location | Notes |
|---|---|---|
| C++ | [`cpp/`](./cpp/) | Built with Visual Studio / MSBuild |
| C# | [`csharp/`](./csharp/) | Built with the .NET 8 SDK |

Both suites cover the same scenarios:

| Sample | Scenario |
|---|---|
| QUERY-PROPERTIES | Read the device's storage and key-count limits |
| AES-GCM-ENCRYPT-DECRYPT | Generate an AES-GCM key, then encrypt and decrypt with it |
| AES-XTS-ENCRYPT-DECRYPT | Generate an AES-XTS key, then encrypt and decrypt with it |
| RSA-IMPORT-ENCRYPT-DECRYPT | Import an RSA key as a wrapped blob, then encrypt and decrypt with it |
| ECDH-KDF-AES | ECDH key exchange, HKDF key derivation, then AES encryption |
| ATTEST-UNWRAP-KEY | Key attestation, then import and use a released key (external services mocked) |
| SECURE-KEY-RELEASE | Full Secure Key Release against Microsoft Azure Attestation and Azure Key Vault |

See each language's README for prerequisites and build instructions.

> Looking for Python? The [`azure_sdk/python/`](../azure_sdk/python/) directory shows how to deploy an AziHSM-enabled VM with the Azure SDK. It does not perform crypto operations against the device.
