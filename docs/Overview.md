# AziHSM Overview

The AziHSM is a Hardware Security Module (HSM) that enables the creation, caching, and usage of cryptography keys within an isolated hardware environment.
Specifically, AziHSM is a physical device that is installed onto the motherboard of Azure host machines.
Cryptographic keys and security assets are cached within the device.
AziHSM has several hardware cryptographic engines that perform encryption, decryption, signing, and other operations.

AziHSM is designed to meet the Federal Information Processing Standards (FIPS) 140-3 Level 3 Security Requirements for Cryptographic Modules.
Cryptographic keys and security assets *never* leave the device, which ensures they are protected while in use, and are isolated from potential adversarial attacks elsewhere on the physical machine.

If your Azure workloads heavily rely on cryptography and have performance intensive workloads, AziHSM provides a secure way to store cryptographic keys for quick and secure retrieval.

## Supported Operations

Please see the [supported algorithms page](./SupportedAlgorithms.md) for a list of the crypto algorithms supported by AziHSM.

## Supported VM SKUs

Please see the [supported SKUs page](./SupportedSKUs.md) for information on the Azure VM SKUs that support AziHSM.

## NCrypt API

The AziHSM KSP (Key Storage Provider) on Windows is invoked via the [Windows NCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/), just like other NCrypt providers like KeyGuard and LSASS.
There are a few notable differences in the behavior of the AziHSM provider when calling it via NCrypt; please see [the NCrypt differences page](./NCryptDifferences.md) for more information.

## Secure Key Release

AziHSM supports securely releasing keys from AKV/mHSM into the AziHSM device.
Please see the [AziHSM SKR page](./SecureKeyRelease.md) for more information.

