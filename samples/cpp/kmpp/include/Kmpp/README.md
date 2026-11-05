AziHSM KMPP Helper Headers
==========================

The header-only helpers in this folder are shared by the KMPP C++ samples. They wrap the three
`libkmpp` entry points and the OpenSSL 3 calls needed to keep a private key inside AziHSM:

| Header | What it provides |
| --- | --- |
| [`Kmpp.h`](./Kmpp.h) | Run-time loader for `libkmpp`, `ProviderContext` (`default` + `kmppprovider`), `KeyId`, `import_key_der`, `load_provider_private_key`, `public_from_key`, RSA-OAEP and SHA-256 sign/verify helpers, and `kmpp::Error`. |
| [`RsaKeys.h`](./RsaKeys.h) | Embedded, throwaway RSA-2048/3072/4096 test keys and `select_rsa()`. Not for production use. |
| [`SampleUtils.h`](./SampleUtils.h) | Sample-only helpers: the sample message, `print_hex`, `import_and_load`, and `run_sample` (shared `main`). |

To reuse them in your own application, copy `Kmpp.h` (it depends only on OpenSSL 3 and `libdl`),
add this folder's parent to the include path, and link with `-lcrypto -ldl`. `libkmpp` does not need
to be present at build time; it is loaded when the first KMPP helper runs.