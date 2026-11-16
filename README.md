# AziHSM Guest

Welcome to the repository for the **Azure Integrated HSM** (**AziHSM**) guest stack.
Here, you'll find:

* [`arm_templates/`](./arm_templates/) - ARM ([Azure Resource Manager](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)) templates to use when deploying an AziHSM-enabled VM.
* [`azure_sdk/`](./azure_sdk/) - Sample code that demonstrates how to deploy an AziHSM-enabled VM with the Azure SDK.
* [`docs/`](./docs/) - Documentation on AziHSM.
* [`samples/`](./samples/) - Small sample applications that demonstrate usage of AziHSM.
* [`scripts/`](./scripts/) - Helpful shell scripts for installing and working with AziHSM.

Azure Integrated HSM (AziHSM) supports Windows and Linux VMs.
See the [Supported Images](./docs/SupportedImages.md) and [Supported SKUs](./docs/SupportedSKUs.md) pages for supported operating system images and Azure VM sizes.

## What is AziHSM?

Please see the [Overview](docs/Overview.md) page to learn more about Azure Integrated HSM.

## Getting Started

### Deploying a VM with AziHSM Enabled

Before you can start using AziHSM, you first need to deploy a VM with AziHSM enabled in Azure.
Please see the [How To Deploy](./docs/HowToDeploy.md) guide to learn how to deploy an AziHSM-enabled VM.

### Installing AziHSM Dependencies

Install the dependencies for your VM's operating system:

| Platform | Dependencies | Installation guide |
|---|---|---|
| Windows | AziHSM device driver, Key Storage Provider (KSP), and SymCrypt | [Windows Install](./docs/InstallWindows.md) |
| Linux | AziHSM device driver, API library, and KMPP for OpenSSL integration | [Linux Install](./docs/InstallLinux.md) |

Both guides include installation verification and uninstall instructions.
On Linux, the installer attempts to install [KMPP (Key Management and Protection Platform)](https://github.com/microsoft/KMPP) by default and requires a package set with the AziHSM backend.

### Running the Samples

To better understand how to use AziHSM in your applications, this repository hosts sample applications for demonstration.

* **Windows:** [C++](./samples/cpp/) and [C#](./samples/csharp/) samples use the AziHSM KSP through Windows CNG/NCrypt.
* **Linux:** [Rust](./samples/rust/kmpp/) and [C++](./samples/cpp/kmpp/) samples use KMPP's OpenSSL 3 provider for RSA encryption/decryption and signing/verification. The Rust samples also demonstrate ECDSA signing/verification.

See the [samples directory](./samples/) for the full list of scenarios and each sample's prerequisites and build instructions.

## Questions & Feedback

Please take a look at our [Frequently Asked Questions](./docs/FAQ.md) page.

If you have any other questions, concerns, or other feedback, please don't hesitate to reach out!
We kindly ask that you submit an issue on this repository; we will get back to you as soon as we are able.

## Trademark Notice

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines.
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party’s policies.