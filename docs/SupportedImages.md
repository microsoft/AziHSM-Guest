# Azure VM Images that Support AziHSM

Azure Integrated HSM currently supports a subset of all available Azure VM images.
The following Operating System images are supported:

* Windows Server 2025
* Azure Linux 3
* Ubuntu 22.04
* Ubuntu 24.04

## Query All Azure Images

Using the Azure CLI, you can view a list of all available OS images using the [`az vm image list` command](https://learn.microsoft.com/en-us/cli/azure/vm/image):

```powershell
az vm image list --all
```

Filter with `--publisher` (or using other command-line options) to narrow down the results:

```powershell
# Windows Server
az vm image list --all --publisher "MicrosoftWindowsServer"
az vm image list --all --offer "WindowsServer"

# Azure Linux
az vm image list --all --publisher "MicrosoftAzureLinux"
az vm image list --all --publisher "MicrosoftCBLMariner"
az vm image list --all --offer "azure-linux-3"
az vm image list --all --sku "azure-linux-3-gen2"

# Ubuntu
az vm image list --all --publisher "Canonical"
```

This will produce output containing JSON objects that should look similar to this:

```json
{
    "architecture": "x64",
    "offer": "WindowsServer",
    "publisher": "MicrosoftWindowsServer",
    "sku": "2025-datacenter",
    "urn": "MicrosoftWindowsServer:WindowsServer:2025-datacenter:26100.32230.260111",
    "version": "26100.32230.260111"
}
```

