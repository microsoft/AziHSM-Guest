# Microsoft Source Code Annotation Language (SAL) in AziHSM

## Overview

This document describes the use of Microsoft Source Code Annotation Language (SAL) annotations in the AziHSM-Guest repository. SAL annotations have been added to C/C++ functions to improve code safety and enable better static analysis.

## What is SAL?

The Microsoft Source Code Annotation Language (SAL) is a set of annotations that describe how a function uses its parameters, what assumptions it makes about them, and what guarantees it makes when it finishes. SAL annotations help static analysis tools like Visual Studio Code Analysis detect potential issues such as buffer overruns, null pointer dereferences, and other common programming errors.

For more information about SAL, see the [official Microsoft documentation](https://learn.microsoft.com/en-us/cpp/code-quality/understanding-sal).

## Language Compatibility

SAL annotations are primarily designed for C/C++ code compiled with the Microsoft Visual C++ compiler. They are defined in the Windows SDK header files and are automatically recognized by:

- **Visual Studio Code Analysis**: Built-in static analysis in Visual Studio
- **PREfast**: Microsoft's static analysis tool
- **Other compatible tools**: Some third-party static analysis tools also support SAL

The annotations are implemented as macros that expand to nothing when compiled with non-Microsoft compilers, ensuring cross-platform compatibility.

## SAL Annotations Used in AziHSM

The following SAL annotations have been applied to functions in the `samples/cpp/include/` directory:

### Input Parameters

- **`_In_`**: Indicates that the parameter is input-only and must be valid.
- **`_In_reads_bytes_(size)`**: Indicates an input buffer with a specific size in bytes that will be read by the function.

### Output Parameters

- **`_Out_`**: Indicates that the parameter is output-only. The function will write to this parameter.
- **`_Out_writes_bytes_(size)`**: Indicates an output buffer with a specific size in bytes that the function will write to.
- **`_Outptr_result_buffer_(size)`**: Indicates that the function will allocate memory and return a pointer to a buffer of the specified size.

### Input/Output Parameters

- **`_Inout_`**: Indicates that the parameter is both input and output. The function reads and modifies it.

### Optional Parameters

- **`_Out_writes_bytes_opt_(size)`**: Similar to `_Out_writes_bytes_`, but the buffer can be NULL to query the required size.

## Files with SAL Annotations

The following files contain SAL-annotated functions:

### `/samples/cpp/include/Utils/Utils.h`

This header file contains utility functions for general operations:

- **`buffer_to_hex()`**: Converts a byte buffer to a hexadecimal string representation
  - `_In_reads_bytes_(buffer_len) BYTE* buffer`: Input buffer to convert
  - `_In_ size_t buffer_len`: Size of the input buffer
  - `_Outptr_result_buffer_(*result_len) char** result`: Output string pointer
  - `_Out_ size_t* result_len`: Length of the output string

- **`randomize_buffer()`**: Fills a buffer with cryptographically random bytes
  - `_Out_writes_bytes_(buffer_len) BYTE* buffer`: Buffer to fill with random data
  - `_In_ size_t buffer_len`: Size of the buffer

### `/samples/cpp/include/Utils/RsaWrapUtils.h`

This header file contains RSA key wrapping utility functions:

- **`CreateAesKey()`**: Creates a random AES key
  - `_Out_ BCRYPT_KEY_HANDLE* outAesKey`: Output AES key handle
  - `_Outptr_result_buffer_(*outBufferAesKeySize) PBYTE* outBufferAesKey`: Output key buffer
  - `_Out_ DWORD* outBufferAesKeySize`: Size of the key buffer

- **`CreateRsaExportKey()`**: Creates an RSA export key from binary data
  - `_In_reads_bytes_(bufferRsaExportKeyBinSize) PBYTE bufferRsaExportKeyBin`: Input binary key data
  - `_In_ DWORD bufferRsaExportKeyBinSize`: Size of the input data
  - `_Out_ BCRYPT_KEY_HANDLE* outRsaExportKey`: Output RSA key handle

- **`EncryptAesWithRsaExportKey()`**: Encrypts an AES key with an RSA public key
  - `_In_reads_bytes_(bufferAesKeySize) PBYTE bufferAesKey`: AES key to encrypt
  - `_In_ DWORD bufferAesKeySize`: Size of the AES key
  - `_In_ BCRYPT_KEY_HANDLE rsaExportKey`: RSA key for encryption
  - `_In_ LPCWSTR algId`: Algorithm identifier
  - `_Outptr_result_buffer_(*outBufferSize) PBYTE* outBuffer`: Encrypted output
  - `_Out_ DWORD* outBufferSize`: Size of the encrypted output

- **`AesKeyWrapPad()`**: Implements RFC 5649 AES key wrapping with padding
  - `_In_ BCRYPT_KEY_HANDLE hAesKey`: AES key handle
  - `_In_reads_bytes_(cbInput) PBYTE pbInput`: Input data to wrap
  - `_In_ ULONG cbInput`: Size of input data
  - `_Out_writes_bytes_opt_(*pcbOutput) PBYTE pbOutput`: Output buffer (can be NULL to query size)
  - `_Inout_ ULONG* pcbOutput`: Input: buffer size / Output: bytes written

- **`CreateBCryptStruct()`**: Constructs a BCRYPT_PKCS11_RSA_AES_WRAP_BLOB structure
  - `_In_reads_bytes_(bufferEncryptedAesKeySize) PBYTE bufferEncryptedAesKey`: Encrypted AES key
  - `_In_ DWORD bufferEncryptedAesKeySize`: Size of encrypted AES key
  - `_In_reads_bytes_(bufferWrappedRsaSize) PBYTE bufferWrappedRsa`: Wrapped RSA key
  - `_In_ DWORD bufferWrappedRsaSize`: Size of wrapped RSA key
  - `_In_ LPCWSTR algId`: Algorithm identifier
  - `_Outptr_result_buffer_(*outSize) PBYTE* out`: Output structure buffer
  - `_Out_ DWORD* outSize`: Size of the output structure

- **`ExportKeyWrapped()`**: Wraps a to-be-imported RSA key in PKCS#11 format
  - `_In_reads_bytes_(bufferToBeImportedKeySize) PBYTE bufferToBeImportedKey`: Key to wrap
  - `_In_ DWORD bufferToBeImportedKeySize`: Size of the key
  - `_In_reads_bytes_(bufferExportKeySize) PBYTE bufferExportKey`: Export key
  - `_In_ DWORD bufferExportKeySize`: Size of export key
  - `_In_ LPCWSTR hashAlgId`: Hash algorithm identifier
  - `_Outptr_result_buffer_(*outKeyBlobSize) PBYTE* outKeyBlob`: Output wrapped key blob
  - `_Out_ DWORD* outKeyBlobSize`: Size of the output blob

## Benefits of SAL Annotations

1. **Improved Code Safety**: SAL helps catch common bugs such as buffer overruns, null pointer dereferences, and use-after-free errors at compile time.

2. **Better Documentation**: The annotations serve as inline documentation, making it clear how functions expect to use their parameters.

3. **Enhanced Static Analysis**: Tools like Visual Studio Code Analysis can provide more accurate warnings and suggestions.

4. **Easier Maintenance**: Future developers can quickly understand parameter usage contracts without reading the entire function implementation.

## Using SAL in Your Code

If you're contributing to the AziHSM-Guest repository and adding new C/C++ functions, please follow these guidelines:

1. **Annotate all function parameters**: Use appropriate SAL annotations for all pointer and array parameters.

2. **Be specific about buffer sizes**: Use `_reads_bytes_` and `_writes_bytes_` variants with size parameters when applicable.

3. **Mark output pointers clearly**: Use `_Out_` or `_Outptr_` to indicate parameters that receive output values.

4. **Consider optional parameters**: Use `_opt_` variants for parameters that can be NULL.

5. **Build with Code Analysis enabled**: Enable `/analyze` flag in Visual Studio to verify your annotations.

## Building with SAL Support

SAL annotations are automatically recognized by the Microsoft Visual C++ compiler when building with Visual Studio. To enable full SAL checking:

1. Open your project in Visual Studio
2. Enable Code Analysis:
   - Right-click the project in Solution Explorer
   - Select "Properties"
   - Go to "Code Analysis" → "General"
   - Set "Enable Code Analysis on Build" to "Yes"
3. Build the project with the `/analyze` compiler flag for enhanced checking

## Additional Resources

- [SAL Annotations Reference](https://learn.microsoft.com/en-us/cpp/code-quality/annotating-function-parameters-and-return-values)
- [Understanding SAL](https://learn.microsoft.com/en-us/cpp/code-quality/understanding-sal)
- [Using SAL Annotations to Reduce C/C++ Code Defects](https://learn.microsoft.com/en-us/cpp/code-quality/using-sal-annotations-to-reduce-c-cpp-code-defects)
- [Best Practices and Examples](https://learn.microsoft.com/en-us/cpp/code-quality/best-practices-and-examples-sal)

## Notes

- SAL annotations are compile-time only and do not affect runtime performance.
- The annotations are designed to work seamlessly with both Microsoft and non-Microsoft compilers.
- When compiled with non-Microsoft compilers, SAL macros expand to nothing, ensuring compatibility.
