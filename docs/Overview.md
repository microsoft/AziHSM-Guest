# AziHSM Overview

**Azure Integrated HSM** (**AziHSM**) is a Hardware Security Module (HSM) that enables the creation, caching, and usage of cryptography keys within an isolated hardware environment.
Specifically, AziHSM is a physical device that is installed onto the motherboard of Azure host machines.

Azure customers can store their cryptographic keys and security assets on AziHSM.
They can then make calls via the AziHSM guest stack to perform cryptographic operations with their keys within the local AziHSM device.
AziHSM has several hardware cryptographic engines that perform encryption, decryption, signing, and other operations.

AziHSM is designed to meet the Federal Information Processing Standards (FIPS) 140-3 Level 3 Security Requirements for Cryptographic Modules.
Cryptographic keys and security assets *never* leave this FIPS 140-3 security boundary, which ensures they are protected while in use, and are isolated from potential adversarial attacks elsewhere on the physical machine.

This security guarantee, plus the performance benefits of running cryptographic operations locally (i.e within the same host machine your VM is running on), makes AziHSM an ideal choice for cryptographic-heavy workloads.

## Questions?

Please take a look at the [Frequently Asked Questions](./FAQ.md) for answers to common questions.

