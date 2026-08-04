# AziHSM FAQ

## Q: What cryptographic operations, keys, etc., are supported by AziHSM?

Please see the [supported algorithms page](./SupportedAlgorithms.md) for a list of the crypto algorithms supported by AziHSM.

## Q: What Azure VM SKUs support AziHSM?

Please see the [supported SKUs page](./SupportedSKUs.md) for information on the Azure VM SKUs that support AziHSM.

## Q: How do I install the AziHSM guest stack?

You may install the AziHSM dependencies onto your VM by following the steps in our install guides:

* [Windows Install](./InstallWindows.md)
* [Linux Install](./InstallLinux.md)

## Q: How do I uninstall the AziHSM guest stack?

You may remove the AziHSM dependencies from your VM by following the steps in our install guides:

* [Windows Install](./InstallWindows.md)
* Linux support is under active development.

## Q: Where can I learn how to use the AziHSM?

Please see the [sample applications](../samples) in this repository.
These provide examples of how the AziHSM can be used for various purposes.

The AziHSM KSP (Key Storage Provider) on Windows is invoked via the [Windows NCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/), just like other NCrypt providers like KeyGuard and LSASS.
There are a few notable differences in the behavior of the AziHSM provider when calling it via NCrypt; please see [the NCrypt differences page](./NCryptDifferences.md) for more information.

## Q: Can I import and use my keys from AKV (Azure Key Vault) / mHSM (Managed Hardware Security Module)?

Yes!
Through a process known as **Secure Key Release** (**SKR**), you can perform attestation and securely import your key from AKV/mHSM into the local AziHSM device connected to your AziHSM-enabled VM.

Please see the [Secure Key Release](./SecureKeyRelease.md) page to learn more.

## Q: How do I collect AziHSM debug logs on my VM?

Both the AziHSM KSP (Key Storage Provider) and the AziHSM device driver produce their own debug output.
This output can be captured and viewed on your VM through [ETW (Event Tracing for Windows)](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal).
To learn how, please see the [event tracing guide](./EventTracing.md).

