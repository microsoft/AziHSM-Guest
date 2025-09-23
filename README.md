# AziHSM Guest

Welcome!

Azure Integrated HSM is now available to use in preview on the AMD v7 preview platform with support for our general purpose Dasv7-series, Dadsv7-series, Easv7-series and Eadsv7-series for 8 vCores Trusted Launch VMs and above. The Azure Integrated HSM preview will initially have Windows support only.
Please sign up for the preview using: https://aka.ms/AMDv7_PublicPreview_Signup and we will enable your subscription to deploy.
 
Please see the AziHSM overview page to learn more about AziHSM.
 
This repository houses sample programs, documentation, and other resources to assist with utilizing the **Azure Integrated Hardware Security Module** (**AziHSM**).
This also houses official releases of the AziHSM binaries, such as the device driver and the KSP (Key Storage Provider) library.
Specifically, you'll find:

* [`arm_templates/`](./arm_templates/) - ARM ([Azure Resource Manager](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)) templates to use when deploying an AziHSM-enabled VM.
* [`azure_sdk/`](./azure_sdk/) - Sample code that demonstrates how to deploy an AziHSM-enabled VM with the Azure SDK.
* [`docs/`](./docs/) - Documentation on the AziHSM.
* [`samples/`](./samples/) - Small command-line applications that demonstrate proper usage of the AziHSM.
* [`scripts/`](./scripts/) - Helpful shell scripts for installing and working with the AziHSM.

Please see the [AziHSM overview page](./docs/Overview.md) to learn more about AziHSM.

## Getting Started

### Deploying a VM with AziHSM Enabled

Before you can start using AziHSM, you would need to deploy a VM with AziHSM enabled in Azure. Please see the [how to deploy guide](./docs/HowToDeploy.md) to learn how to deploy an AziHSM-enabled VM.

### Installing AziHSM Dependencies

To utilize the AziHSM on your Azure VM, you'll need to install the necessary dependencies.
Please see the [installation guide](./docs/Install.md) for more information (and for steps on how to uninstall).

### Running the Samples

To run the samples, please see [instructions for running samples](./samples/cpp).


## Questions & Feedback

Please take a look at our [frequently asked questions](./docs/FAQ.md) page.

If you have any other questions, concerns, or other feedback, please don't hesitate to reach out!
We kindly ask that you submit an issue on this repository; we will get back to you as soon as we are able.

## Trademark Notice

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines.
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party’s policies.

