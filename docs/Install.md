# Installing AziHSM Dependencies

Before you can run any of the samples in this repository, you'll need to ensure that the following dependencies are installed onto your machine:

* AziHSM **device driver**
* AziHSM **KSP** (Key Storage Provider)
* [SymCrypt](https://github.com/microsoft/SymCrypt) - A dependency of the AziHSM KSP

Please perform the following steps:

1. Download the [`install-azihsm.ps1`](../scripts/install-azihsm.ps1) script from this repository onto your VM.
2. Download all files from one of [this repository's releases](https://github.com/microsoft/AziHSM-Guest/releases) onto your VM.
3. Place the downloaded `.zip` and `.nupkg` files under a single directory on your VM.
4. Open PowerShell (v5.1+) with *admin privileges* on your VM and navigate PowerShell to this directory.
5. Execute the installation script.

The PowerShell script will search your shell's working directory (`$pwd`) for the downloaded files, extract the contents, and locate the needed binary files.
It will then use these files to install all AziHSM dependencies.
If existing AziHSM device driver and/or KSP binaries are currently installed on your machine, they will be uninstalled, and the new versions will be installed.

## How do I verify the installation?

If the installation script completed successfully, no verification is required.
However, if you would like to double-check, follow these steps.

### Verify AziHSM KSP

First, open PowerShell or File Explorer, and ensure the AziHSM KSP DLL is located in `C:\Windows\System32`:

```powershell
ls C:\Windows\System32\azihsmksp.dll
```

Next, in PowerShell run the following [`certutil`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) command:

```powershell
certutil -csplist
```

This will list all Cryptographic Service Providers (CSPs) installed on your machine.
Look for this provider name in the command's output:

```
Microsoft Azure Integrated HSM Key Storage Provider
```

If this is present, then the AziHSM KSP is installed correctly.

If it is *not* present, then the AziHSM KSP is not registered with the system as a key storage provider.
Try following the installation guide again; watch for errors that appear when running the installation script.
(The script uses the [`regsvr32`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32) command-line tool to register the KSP DLL with the OS; look for script output regarding any error status codes or messages.)

#### Debug `regsvr32` Failures

If driver installation failed, try these commands in a PowerShell instance (with administrator privileges) to manually debug the KSP registration with the OS.

```powershell
# To register AziHSM KSP with the OS:
regsvr32 C:\Windows\System32\azihsmksp.dll

# To unregister AziHSM KSP:
regsvr32 /u C:\Windows\System32\azihsmksp.dll
```

In GUI-enabled Windows systems, a dialog box should appear with a success or failure message.

### Verify AziHSM Device Driver

In PowerShell, run the following [`pnputil`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pnputil) command:

```powershell
pnputil /enum-drivers
```

Look in the output for a driver whose `Original Name` is `azihsmvf.inf`.
It should look similar to this:

```
Published Name:     oemXX.inf
Original Name:      azihsmvf.inf
Provider Name:      Microsoft
Class Name:         SecurityDevices
Class GUID:         {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
Driver Version:     MM/DD/YYYY 2.0.XXX.0
Signer Name:        Microsoft Windows Hardware Compatibility Publisher
```

If you do *not* see this, then the AziHSM driver is not properly installed onto the system.
Try following the installation guide again; watch for errors that appear when running the installation script.
If you are still encountering issues, try following the official [Device and Driver Installation Troubleshooting Guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/troubleshooting-device-and-driver-installations).
If all else fails, please feel free to submit an issue to this GitHub repository.

### Verify SymCrypt

In PowerShell or File Explorer, ensure the SymCrypt DLL is located in `C:\Windows\System32`:

```powershell
ls C:\Windows\System32\symcrypt.dll
```

## How do I uninstall?

To uninstall the AziHSM dependencies from your VM, perform the following steps:

1. Download the [`uninstall-azihsm.ps1`](../scripts/uninstall-azihsm.ps1) script from this repository onto your VM.
2. Execute the script.

