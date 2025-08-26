# AziHSM FAQ

## Q: How do I install the AziHSM?

You may install the AziHSM dependencies onto your VM by following the steps in our [install guide](./Install.md).

## Q: How do I uninstall the AziHSM?

You may remove the AziHSM dependencies from your VM by following the steps in our [install guide](./Install.md).

## Q: Where can I learn how to use the AziHSM?

Please see the [sample applications](./samples) in this repository.
These provide examples of how the AziHSM can be used for various purposes.

## Q: How do I collect AziHSM debug logs?

Both the AziHSM KSP (Key Storage Provider) and the AziHSM device driver produce their own debug output.
This output can be captured and viewed on your VM through [ETW (Event Tracing for Windows)](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal).
To learn how, please see the [event tracing guide](./EventTracing.md).

