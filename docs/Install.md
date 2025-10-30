# Installing AziHSM Dependencies

Before you can run any of the samples in this repository, you'll need to ensure that the following dependencies are installed onto your machine:

* AziHSM **device driver**
* AziHSM **KSP** (Key Storage Provider)
* [SymCrypt](https://github.com/microsoft/SymCrypt) - A dependency of the AziHSM KSP

Please perform the following steps:

1. Download the [`install-azihsm.ps1`](../scripts/install-azihsm.ps1) script from this repository onto your VM.
2. Open PowerShell (v5.1+) with *admin privileges* on your VM and run the script.

The script will automatically download compatible AziHSM driver, AziHSM KSP, and SymCrypt binaries and install them.
If existing AziHSM device driver and/or KSP binaries are currently installed on your machine, they will be uninstalled, and the new versions will be installed.

## How does the script work?

<details>
<summary>(Click here for Technical Details)</summary>

The script follows this algorithm:

1. Download an AziHSM device driver from GitHub, and install it.
2. Download and execute the AziHSM `get_device_info.exe` command-line utility.
   This informs the script what firmware version the connected AziHSM device is running.
3. Determine if the current device driver version is compatible with the firmware version.
    1. If it is, then the driver install is complete.
    2. If it's not, download a compatible driver version, and install it (replacing the current version).
3. Download and install SymCrypt.
4. Download an AziHSM KSP version that is compatible with the firmware, and install it.

The firmware version is needed in order to determine AziHSM device driver and KSP compatibility.
However, retrieving the firmware version requires a device driver to be installed.
So, an arbitrary AziHSM device driver (usually the latest version) is temporarily installed, to be used to run `get_device_info.exe`.
Once the firmware version is known, the driver is either kept, or replaced, based on compatibility.

</details>

## What if my VM is unable to download from GitHub?

<details>
<summary>(Click to Expand)</summary>

If the `install-azihsm.ps1` script is unable to download release binaries from GitHub, you may also download them manually and point the install script at them.
Please perform the following steps:

1. Download AziHSM driver and AziHSM binary files from [this repository's releases](https://github.com/microsoft/AziHSM-Guest/releases) and copy them to your VM.
    * It is recommended that you download the latest release of these binaries.
2. Download the AziHSM `get_device_info` tool [this repository's releases](https://github.com/microsoft/AziHSM-Guest/releases) and copy them to your VM.
3. Download SymCrypt binaries from [the SymCrypt repository's release](https://github.com/microsoft/SymCrypt/releases) and copy them to your VM.
4. Open PowerShell (v5.1+) with *admin privileges* on your VM and use the following arguments to point the script at your downloaded files.
    * `-KSPPath C:\path\to\azihsm.ksp.plugin.x86_64.X.X.XXX.[zip|nupkg]`
    * `-DriverPath C:\path\to\azihsm.windows.vf.driver.x86_64.X.X.XXX.[zip|nupkg]`
    * `-GetDeviceInfoPath C:\path\to\azihsm.get_device_info.x86_64.X.X.XXX.[zip|nupkg]`
    * `-SymCryptPath C:\path\to\symcrypt.dll`

The script will extract the contents and install all binaries.

**NOTE:** Pay attention to the information printed in the **Device Information Discovery** section of the script's output.
This will tell you what driver and KSP versions are compatible with the AziHSM device connected to your VM.
Normally, the script will automatically decide which versions to install, but it won't be able to do this if it cannot download files from GitHub.
This means it is possible that the driver versions you manually downloaded are not compatible.
You may see these warnings:

```
WARNING: The current AziHSM driver version ("X.X.XXX.X") is NOT compatible with the device firmware version ("X.Y-ZZZZZZZZ"). Compatible driver versions are between "X.X.XXX.X" and "X.X.XXX.X"
WARNING: The current AziHSM KSP version ("X.X.XXX.X") is NOT compatible with the device firmware version ("X.Y-ZZZZZZZZ"). Compatible KSP versions are between "X.X.XXX.X" and "X.X.XXX.X"
```

If this is the case, please download compatible versions and repeat the steps above to complete the installation.

</details>

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
Driver Version:     MM/DD/YYYY X.X.XXX.X
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

