# Differences in NCrypt Behavior with AziHSM

You may already be familiar with [Windows NCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/) when using KeyGuard or LSASS providers.
You may already have workloads that interface with these providers.

Due to the implementation and security implications of the Azure Integrated HSM, there are some differences in how the NCrypt API must be used while interacting with AziHSM.
This document summarizes the key differences to keep in mind when developing an NCrypt workload to work with the AziHSM; they are also demonstrated in the [sample applications](../samples/).

## Only Use Supported Algorithms

The AziHSM device does not support the same algorithm set as KeyGuard, LSASS, or other providers.
Please see [supported algorithms page](./SupportedAlgorithms.md) for a list of the crypto algorithms supported by AziHSM.

## Import (Don't Create) RSA Keys

The AziHSM device does not support generation of RSA keys.
However, you can import an RSA key that was generated elsewhere into the device.
Once imported, the AziHSM can use this key for performing RSA crypto operations.

Internally, the device generates a single RSA key when initialized; this RSA key is known as the "built-in unwrap key".
Its purpose is to be used as the `hImportKey` with [`NCryptImportKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey) to unwrap encrypted key data when importing.
(It cannot be used to decrypt or sign.)

The AziHSM device only supports importing keys in PKCS#11 encrypted format.
This format is specified in the [PKCS#11 specification](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908).

To understand how the import process works, please see the [RSA-IMPORT-ENCRYPT-DECRYPT sample application](../samples/cpp/RSA-IMPORT-ENCRYPT-DECRYPT/README.md).

## AES-GCM Encryption - IV (Initialization Vector) - Fill with Zeroes

When performing an AES-GCM encryption operation, the AziHSM device will generate an IV (Initialization Vector) rather than accepting one provided by the caller.
This internally-generated IV is then returned to the caller through the parameters to [`NCryptEncrypt`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptencrypt).
The caller can then use this IV to perform decryption by passing it into [`NCryptDecrypt`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptdecrypt).

Because the caller is *receiving* an IV, rather than *providing* one, the caller must initialize their IV buffer to contain all zeroes.
To understand how this works, please see the [AES-GCM-ENCRYPT-DECRYPT sample application](../samples/cpp/AES-GCM-ENCRYPT-DECRYPT/README.md).

## HKDF Key Derivation Data (`NCryptDeriveKey`)

The AziHSM device supports a single Key Derivation Function (KDF): HKDF specified in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
The AziHSM provider exposes this function through the [`NCryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptderivekey) function.

However, the AziHSM provider does not return raw key data from [`NCryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptderivekey) unlike other NCrypt providers.
Instead, the AziHSM returns bytes that represent a key handle.
This key handle can then be passed into [`NCryptImportKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey) to obtain a handle on the derived+imported key for using it.

This is done to ensure the derived key's data does not leave the secure hardware-isolated environment of the physical AziHSM device.
To understand how this process works, please see the [ECDH-KDF-AES sample](../samples/cpp/ECDH-KDF-AES/README.md).

## Don't Use Named Keys

KeyGuard supports storing a key persistently if the user specifies a key name when calling [`NCryptCreatePersistedKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey) or [`NCryptImportKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey).
The AziHSM provider does not currently support persistent storage.
The AziHSM provider will return an error if key name is set when creating or importing a key.

All AziHSM keys are ephemeral.
This means key data will be released when calling [`NCryptFreeObject`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject) on a key handle, or calling `NCryptFreeObject` on the AziHSM provider handle.

## Set Usage on Keys before Finalizing

The AziHSM device requires key usage to be defined during key creation.
This means a given key can only be used for one type of operation.
In other words, a key can support decrypt or sign, but not both.

The usage can be configured by setting the `NCRYPT_KEY_USAGE_PROPERTY` on a key before calling [`NCryptFinalizeKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfinalizekey).
When importing a key, [`NCryptImportKey`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey) must be used with the `NCRYPT_DO_NOT_FINALIZE_FLAG` to set properties before finalizing.

If unset, the AziHSM provider will assume reasonable defaults for most key types.
By default, RSA keys are configured to support signing.
See the [RSA-IMPORT-ENCRYPT-DECRYPT sample application](../samples/cpp/RSA-IMPORT-ENCRYPT-DECRYPT/README.md) to learn how to set a key's usage.

