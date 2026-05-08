#  Sample - QUERY-PROPERTIES

This sample demonstrates querying of the following properties that AziHSM exposes to user:

| Property (string)                       | Description                                              | Content                                                                 |
|-----------------------------------------|----------------------------------------------------------|-------------------------------------------------------------------------|
| AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY | Maximum storage capacity of the device, in Kilo Bytes.   | 4 bytes buffer holding unsigned 32-bit integer. Little Endian.          |
| AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY    | Maximum number of keys can be stored on the device.      | 4 bytes buffer holding unsigned 32-bit integer. Little Endian.          |

There are other properties that are tied to keys:

1. "RsaCrtEnabled": See ATTEST-UNWRAP-RSA sample for its usage.

## How to run

> See top-level [README.md](../README.md) for prerequisites.

This sample takes no additional arguments.

Example output:
> You actual number may vary depending on your specific AziHSM configuration.

```
AziHSM Demonstration: Querying properties
=========================================

Open AziHSM Provider
--------------------
Opened NCrypt Storage Provider handle: 0x0fee6ac0

Query AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY
---------------------------------------------
Max Storage Size: 16 Kilo Bytes

Query AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY
------------------------------------------
Max Key Count: 256
```
