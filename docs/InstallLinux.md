# Installing AziHSM Dependencies on Linux VMs

Before you can use AziHSM on a Linux VM, you'll need to ensure that the following dependencies are installed onto your machine:

* AziHSM **device driver**
* AziHSM **API library**
* [KMPP](https://github.com/microsoft/KMPP) (**Key Management and Protection Platform**)

To install these dependencies, please perform the following steps:

1. Download the [`install-azihsm.sh`](../scripts/install-azihsm.sh) script from this repository onto your VM.

    ```bash
    curl --fail --location --output install-azihsm.sh https://raw.githubusercontent.com/microsoft/AziHSM-Guest/main/scripts/install-azihsm.sh
    ```

2. Open `bash` and execute the script with root privileges (`sudo ./install-azihsm.sh`).

The script will automatically connect to [packages.microsoft.com](https://packages.microsoft.com) ("PMC"), locate the correct packages, and install them onto your machine.

## KMPP

KMPP (Key Management and Protection Platform) is a separate software system developed by Microsoft.
It supports AziHSM and is the recommended solution for utilizing it on Linux.
The installer attempts KMPP installation by default, but installs only a complete package set whose runtime contains the AziHSM backend.
Because older versions of KMPP do not support AziHSM, installation may fail.

* To skip KMPP installation, use `--skip-kmpp`.
* To include development dependencies in the required package set, use `--kmpp-install-dev`.
* To learn more about KMPP, see the [official KMPP repository](https://github.com/microsoft/KMPP).

> **NOTE:** The installer configures KMPP such that it is *not* the default system-wide OpenSSL provider.
>
> As such, in order to use AziHSM via KMPP, you will need to *explicitly* select KMPP as the OpenSSL provider when developing applications and invoking `openssl` on the command-line.
> See these resources for more information:
>
> * [OpenSSL Documentation - Provider implementations](https://docs.openssl.org/master/man7/provider/)
> * [OpenSSL CLI Documentation](https://docs.openssl.org/3.3/man1/openssl/#provider-options) (See the `-provider` option)
> * See this repository's [KMPP sample applications](../samples) to learn how you can configure your application

After KMPP packages install successfully, the script creates `/var/opt/msft/ap/data/kmpp/config.cnf`, which configures KMPP to use AziHSM while leaving default activation disabled.

The AziHSM uninstaller leaves all KMPP packages, services, accounts, configuration, markers, and data untouched.
KMPP is managed separately; follow the [official KMPP repository](https://github.com/microsoft/KMPP) for KMPP-specific management and uninstall guidance.

## What if my VM is unable to download from PMC?

The script will create the necessary configurations on your VM to access PMC.
If your VM is unable to access the internet, or otherwise cannot properly download packages, you may also download the packages from PMC manually (i.e. from a browser or a different machine), copy them onto your VM, and point the install script at them.

Use `--driver-path PATH...`, `--api-path PATH...`, or `--kmpp-path PATH...` to install one or more local `.deb` or `.rpm` packages for each component.
Each `--*-path` option accepts more than one file path.

For example, see these commands, which install all three dependencies (driver, API library, and KMPP) all from local `.rpm`/`.deb` files:

```bash
# Azure Linux (.rpm)
./install-azihsm.sh --driver-path "./azihsm-driver-6.6.159.1-1.azl3-3.2.190.0-1.azl3.x86_64.rpm" "./azihsm-driver-common-3.2.195.0-1.azl3.x86_64.rpm" --api-path "./libazihsmr-3.2.195.0-1.azl3.x86_64.rpm" --kmpp-path "./kmpp-5.1.1_296-1.x86_64.rpm"

# Ubuntu (.deb)
./install-azihsm.sh --driver-path "./azihsm-module-6.8.0-1070-azure_3.2.195.0+jammy_amd64.deb" "./azihsm-module-common_3.2.195.0+jammy_amd64.deb" --api-path "libazihsmr_3.2.195.0+jammy_amd64.deb" --kmpp-path "libkmpp_5.1.1-296-1_amd64.deb"
```

Please run the install script with `--help` to view full set of command-line arguments:

```bash
./install-azihsm.sh --help
```

## How do I verify the installation?

### Verify the AziHSM Device Driver

<details>
<summary>(Click to Expand)</summary>

#### 1. Ensure Driver is Installed

In bash, run the following command to check for the presence of the `azihsm` driver module:

```bash
lsmod | grep "azihsm"
```

This should show output similar to this:

```
azihsm                151552  0
```

Run this command to check the driver version:

```bash
cat /sys/module/azihsm/version
```

This should produce output with an `A.B.C.D`-style version number, such as:

```
3.2.157.0
```

#### 2. Ensure AziHSM Device is Present

Next, look for the AziHSM device under `/dev`:

```bash
ls -al /dev/azihsm*
```

This should yield output similar to this:

```
crw-rw---- 1 root azihsm 240, 0 Sep 14 17:28 /dev/azihsm0
```

#### 3. Check for Driver Logs

Lastly, you can use `dmesg` to search for logs produced by the AziHSM driver.
This is a good way to confirm the driver loaded and running; it is also a good way to check for driver errors.

First, get the version of the driver that is currently loaded:

```bash
driver_version="$(cat /sys/module/azihsm/version)"
```

Next, use `dmesg` to retrieve log messages from the driver:

```bash
sudo dmesg | grep -F -e "azihsm" -e "${driver_version}"
```

This should yield output similar to this:

```
[  297.706115] azihsm 7223:00:00.0: [3.2.157.0 | azihsm_ctrl_disable_enabled_controller] [azihsm_ctrl_disable_enabled_controller ctrl:00000000e233f3cc CSTS REGISTER VALUE:0x1 CC REGISTER VALUE:0x67460001
[  297.707752] azihsm 7223:00:00.0: [3.2.157.0 | azihsm_ctrl_disable_enabled_controller] [controller enabled. Disabling] azihsm_ctrl_disable_enabled_controller azihsm_ctrl:00000000e233f3cc
[  297.709407] azihsm 7223:00:00.0: [3.2.157.0 | azihsm_ctrl_hw_wait_ready] controller disabled [CSTS:0x0]
[  297.710285] azihsm 7223:00:00.0: [3.2.157.0 | azihsm_ctrl_disable_enabled_controller] [EXIT] azihsm_ctrl_disable_enabled_controller azihsm_ctrl:00000000e233f3cc return value:0
[  297.711771] azihsm 7223:00:00.0: [3.2.157.0 | azihsm_ctrl_hw_wait_ready] controller enabled [CSTS:0x1]
```

Alternatively, you can use `journalctl` to read the driver logs as well:

```bash
sudo journalctl -k -b -o short-precise --no-pager | grep -F -e "azihsm" -e "${driver_version}"
```

</details>

### Verify the AziHSM API Library

<details>
<summary>(Click to Expand)</summary>

To verify that the AziHSM API Library was installed correctly, look in the following locations:

```bash
find /usr/lib -name "libazihsm_api_resilient.so*"
find /usr/lib64 -name "libazihsm_api_resilient.so*"
```

The API library (`libazihsm_api_resilient.so`) is installed into the Linux system's default library location.
If that location is *not* `/usr/lib/`, then the Linux packages will create a symlink during setup.

Similarly, if you installed the development dependencies to go along with the API Library (meaning, you ran the install script with `--api-install-dev`), then a C/C++ header file will also be installed as `azihsm_api_resilient.h`.
You can locate it by running this command:

```bash
find /usr/include -name "azihsm_api_resilient.h"
```

</details>

### Verify User Groups

<details>
<summary>(Click to Expand)</summary>

The install script will, by default, add the current user to the `azihsm` and `tss` Linux user groups.
These groups are needed for:

* `azihsm` - Needed to access the `/dev/azihsm*` devices (which are exposed by the driver) *without* needing root permissions.
* `tss` - Needed to access the TPM device(s) on your VM *without* needing root permissions.
    * **Why do I need access to the TPM**?
      The AziHSM API Library communicates with the TPM when certain changes are made to your Virtual Machine, such as when it is "Live Migrated" (moved from one server node to another).
      The TPM ensures the AziHSM partition for your VM is properly, and securely kept intact.

To verify your user account has been added to these groups, run `groups`:

```bash
groups
```

You should see both `azihsm` and `tss` in the output.
For example:

```
azureuser cdrom sudo audio video plugdev tss netdev lxd azihsm
```

**NOTE:** If you are running this in the same shell session you ran `install-azihsm.sh`, you will need to restart your shell or re-login to the VM in order for the group changes to take effect.

</details>

### Verify KMPP

<details>
<summary>(Click to Expand)</summary>

When a supported package set is available, the installer checks that the runtime library, KMPP's AziHSM backend, and provider exist, then performs an explicit OpenSSL 3 provider load.
KMPP is not a default provider and must be loaded explicitly by applications using OpenSSL.
If installation reported that KMPP was skipped, there is no KMPP readiness result to verify.

To verify the KMPP OpenSSL provider is installed, first locate `kmppprovider.so` in the package file list:

```bash
provider_path="$(dpkg-query -L libkmpp 2>/dev/null | grep '/ossl-modules/kmppprovider.so$' ||
    rpm -ql kmpp 2>/dev/null | grep '/ossl-modules/kmppprovider.so$')"
```

Then, use its directory in an `openssl` command

```bash
sudo env OPENSSL_CONF=/dev/null openssl list -providers \
    -provider-path "${provider_path%/*}" \
    -provider default \
    -provider kmppprovider
```

Confirm that the installed runtime also supplies the AziHSM backend:

```bash
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -L libkmpp | grep '/libkmpp_azihsm.so$'
else
    rpm -ql kmpp | grep '/libkmpp_azihsm.so$'
fi
```

If your system is running `systemd`, the main `dbus-com.microsoft.kmpp.service` should be active.
Run this command to check:

```bash
systemctl is-active dbus-com.microsoft.kmpp.service
```

For troubleshooting application operations, see [Collecting KMPP Logs on Linux](./KMPPLogging.md).

</details>

## How do I uninstall?

The uninstall script leaves package-owned API library links to the native package manager and verifies their removal.

To uninstall the AziHSM dependencies from your VM, perform the following steps:

1. Download the [`uninstall-azihsm.sh`](../scripts/uninstall-azihsm.sh) script from this repository onto your VM.
2. Execute the script.

**NOTE:** The AziHSM uninstaller leaves KMPP untouched because KMPP is managed separately.
See the [official KMPP repository](https://github.com/microsoft/KMPP) for KMPP-specific management and uninstall guidance.
