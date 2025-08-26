// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This header file defines globals used to interact with the Azure Integrated
// HSM (AziHSM) through the Windows NCrypt API.
//
// These values are not included in the NCrypt interface by default. Thus,
// including this header file is necessary to utilize the full set of features
// implemented by the AziHSM.
//
// For more information, see these links:
//
// * [NCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt)


#pragma once
#include <string>

// The name of the AziHSM Key Storage Provider.
//
// This should be passed into `NCryptOpenStorageProvider()` as the provider
// name in order to open a handle to the AziHSM KSP.
#define _AZIHSM_KSP_NAME L"Microsoft Azure Integrated HSM Key Storage Provider"
const wchar_t* AZIHSM_KSP_NAME = _AZIHSM_KSP_NAME;


// ========================== Provider Properties =========================== //
// This section defines strings that represent the names of provider-level
// properties made available by the AziHSM. These properties are read-only, and
// cannot be modified.
//
// To access each of these properties, pass the appropriate string into
// `NCryptGetProperty()`, as the property name.

// The name of the property that holds the AziHSM's device cert chain.
#define _AZIHSM_PROPERTY_CERT_CHAIN_NAME L"AZIHSM_DEVICE_CERT_CHAIN_PROPERTY"
const wchar_t* AZIHSM_PROPERTY_CERT_CHAIN_NAME = _AZIHSM_PROPERTY_CERT_CHAIN_NAME;

// The name of the property that holds maximum number of keys the device can
// store at one time.
//
// The property's value is an unsigned 32-bit integer (4 bytes in length), and
// is represented in little-endian ordering.
#define _AZIHSM_PROPERTY_MAX_KEY_COUNT_NAME L"AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY"
const wchar_t* AZIHSM_PROPERTY_MAX_KEY_COUNT_NAME = _AZIHSM_PROPERTY_MAX_KEY_COUNT_NAME;

// The name of the property that holds maximum storage size, in Kilobytes (KB),
// in which keys can be stored on the AziHSM device.
//
// The property's value is an unsigned 32-bit integer (4 bytes in length), and
// is represented in little-endian ordering.
#define _AZIHSM_PROPERTY_MAX_STORAGE_SIZE_NAME L"AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY"
const wchar_t* AZIHSM_PROPERTY_MAX_STORAGE_SIZE_NAME = _AZIHSM_PROPERTY_MAX_STORAGE_SIZE_NAME;


// ============================= Key Properties ============================= //
// This section defines strings that represent the names of key-specific
// properties made available by the AziHSM.

// A custom key property, exclusively for RSA keys, that determines if an RSA
// key should be imported as CRT-enabled or CRT-disabled. "CRT" ("Chinese
// Remainder Theorem") is an optimization on RSA keys that allows for faster
// computation, at the cost of requiring more space to store the key.
//
// By default, RSA keys are imported into the AziHSM as CRT-enabled. To
// explicitly set this property, it should be done via `NCryptSetProperty()`,
// *after* `NCryptImportKey()` is called, and *before* `NCryptFinalizeKey()` is
// called.
#define _AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED L"RsaCrtEnabled"
const wchar_t* AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_NAME = _AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED;

// The value that is returned from `NCryptGetProperty()` for the `RsaCrtEnabled`
// property for an RSA key, when it is CRT-enabled.
//
// This value can also be used to enable CRT during RSA key import via the
// `NCryptSetProperty()` function, *after* `NCryptImportKey()` is called, and
// *before* `NCryptFinalizeKey()` is called.
#define _AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED 1
const uint32_t AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED = _AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED;

// The value that is returned from `NCryptGetProperty()` for the `RsaCrtEnabled`
// property for an RSA key, when it is CRT-disabled.
//
// This value can also be used to disable CRT during RSA key import via the
// `NCryptSetProperty()` function, *after* `NCryptImportKey()` is called, and
// *before* `NCryptFinalizeKey()` is called.
#define _AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_DISABLED 0
const uint32_t AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_DISABLED = _AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_DISABLED;


// ======================== Built-In Unwrapping Key ========================= //
// This section defines values used to import key blobs into AziHSM, as well as
// the name of the built-in AziHSM unwrapping key.
//
// Each AziHSM device has a built-in unwrapping key, which is used internally to
// unwrap encrypted blobs that contain keys imported by the user.

// The name of the AziHSM's built-in unwrapping key.
//
// This can be passed into `NCryptOpenKey()` to open a handle to the key, which
// can then be used in `NCryptExportKey()` to export the public key contents
// and use it to encrypt a key blob before importing it.
#define _AZIHSM_BUILTIN_UNWRAP_KEY_NAME L"AZIHSM_BUILTIN_UNWRAP_KEY"
const wchar_t* AZIHSM_BUILTIN_UNWRAP_KEY_NAME = _AZIHSM_BUILTIN_UNWRAP_KEY_NAME;

// The name of the blob type used when importing a derived key after a Key
// Derivation Function (KDF) operation.
//
// When using this blob type, AziHSM interprets the parameters of
// `NCryptImportKey()` differently than as described by the NCrypt API. In this
// context, the `pbData` and `cbData` parameters into `NCryptImportKey()`
// should contain an internal key handle, rather than the derived data itself.
#define _AZIHSM_DERIVED_KEY_IMPORT_BLOB_NAME L"AzIHsmDerivedKeyImportBlob"
const wchar_t* AZIHSM_DERIVED_KEY_IMPORT_BLOB_NAME = _AZIHSM_DERIVED_KEY_IMPORT_BLOB_NAME;

