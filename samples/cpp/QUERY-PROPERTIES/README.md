AziHSM Sample - QUERY-PROPERTIES
================================

This sample demonstrates querying of the following properties that AziHSM exposes to user:


| Property (string)                       | Description                                              | Content                                                                 |
|-----------------------------------------|----------------------------------------------------------|-------------------------------------------------------------------------|
| AZIHSM_DEVICE_CERT_CHAIN_PROPERTY       | Certificate chain of the device. Useful for attestation. | List of certificates in PEM format, separated by `\n`. Leaf cert first. |
| AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY | Maximum storage capacity of the device, in Kilo Bytes.       | 4 bytes buffer holding unsigned 32-bit integer. Little Endian.          |
| AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY    | Maximum number of keys can be stored on the device.      | 4 bytes buffer holding unsigned 32-bit integer. Little Endian.          |

There are other properties that are tied to keys:

1. "RsaCrtEnabled": See ATTEST-UNWRAP-RSA sample for its usage.

Building & Running the Code
---------------------------

### Prerequisite - AziHSM Dependencies

Before you can run this sample, you'll need to ensure you have all AziHSM dependencies installed onto your system.
Please the the installation guide under `docs/` in this repository.

### Building & Running

To build the code, you'll need to download both *this* sample's directory, as well as the `include/` directory, which contains the required header files.
We recommend downloading the entire `samples/` directory, to maintain the directory hierarchy expected by the individual Visual Studio projects.
(This Visual Studio project is configured to search for the AziHSM `include/` directory one level above the project directory. However, if necessary, [this can be changed in the project settings](https://learn.microsoft.com/en-us/cpp/build/working-with-project-properties).)

Locate the Visual Studio Solution (`.sln`) file within this directory.
Launch Visual Studio and open the Solution file.
This will populate Visual Studio with the sample project's contents.

Build and run the project with `F5`, or by selecting `Build > Build Solution`.
An executable will be produced within the project directory, which can be executed on the Windows command-line (PowerShell or Command Prompt).

You should see output similar to this:

<details>
<summary>(Click here)</summary>

You actual number may vary depending on your specific AziHSM configuration.

```
AziHSM Demonstration: Querying properties
=========================================

Open AziHSM Provider
--------------------
Opened NCrypt Storage Provider handle: 0x0fee6ac0

Query AZIHSM_DEVICE_CERT_CHAIN_PROPERTY
---------------------------------------
Retrieved AZIHSM_DEVICE_CERT_CHAIN_PROPERTY successfully. Buffer size: 619

Query AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY
---------------------------------------------
Max Storage Size: 16 Kilo Bytes

Query AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY
------------------------------------------
Max Key Count: 256
```

</details>

Included Header Files
---------------------

You'll notice that the sample's C++ file includes multiple header files:

* `AziHSM.h`
    * This header file defines several strings that are necessary for interfacing with the AziHSM via NCrypt.
    * For more information on this file, please see [this README](../include/AziHSM/README.md).

