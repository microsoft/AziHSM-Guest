# How to deploy a VM with Azure Integrated HSM

Azure Integrated HSM is a Hardware Security Module (HSM) cache and crypto accelerator designed to enhance the security and performance of cryptographic operations in virtual machines.
For customers who heavily rely on cryptography and have performance-intensive workloads, Azure Integrated HSM provides a secure way to store cryptographic keys for quick and secure retrieval.
This feature is available as part of our [AMD Dasv7, Dadsv7, Easv7 and Eadsv7 series preview](https://techcommunity.microsoft.com/blog/azurecompute/announcing-preview-of-new-azure-dasv7-easv7-fasv7-series-vms-based-on-amd-epyc%E2%84%A2-/4448360).
Please ensure you have filled out the [preview form](https://forms.office.com/pages/responsepage.aspx?id=v4j5cvGGr0GRqy180BHbRyMSy8VejZVEo6yZykiPSHpUQkI0VFlXTVVVUlhDMVg5SkRYSTFPNEJHQi4u&route=shorturl) and indicated Azure Integrated HSM support.

Note: In order for a VM to use Azure Integrated HSM, please include a tag `platformsettings.host_environment.AzureIntegratedHSM=True` *at the time of deployment*.
Adding the tag to the VM after the VM has been deployed will result in the VM not being able to use Azure Integrated HSM.

## 1. Create a resource group

Create a resource group with the `az group create` command.
An Azure resource group is a logical container into which Azure resources are deployed and managed.
The following example creates a resource group named `myResourceGroup` in the `eastus2` location:

(**Note:** AMD v7 VMs are not available in all locations.
For currently supported locations, see which VM products are available by Azure region.)

```powershell
az group create --name myResourceGroup --location eastus2
```

## 2. Create general purpose VM with Azure Integrated HSM feature enabled

### Option 1 - Azure CLI

Create a VM with the `az vm create` command.

The following example creates a VM named `myVM` and adds a user account named `azureuser`.
For sizes, Azure Integrated HSM is supported by 8 vCores and above for the following SKUs:

* [Dasv7](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dasv7-series)
* [Dadsv7](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dadsv7-series)
* [Easv7](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/memory-optimized/easv7-series)
* [Eadsv7](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/memory-optimized/eadsv7-series)

Once our team has contacted you and enabled the Azure Integrated HSM tag mentioned below for your subscription you can use it to create new VM deployments.
The VMs must support TrustedLaunch and secure boot in order to support Azure Integrated HSM.

```powershell
az vm create `
    --resource-group myResourceGroup `
    --name myVM `
    --size Standard_D8as_v7 `
    --admin-username azureuser `
    --admin-password <password> `
    --enable-vtpm true `
    --image "MicrosoftWindowsServer:WindowsServer:2025-datacenter-smalldisk-g2:latest" `
    --public-ip-sku Standard `
    --security-type TrustedLaunch `
    --location eastus2 `
    --enable-secure-boot true `
    --tags platformsettings.host_environment.AzureIntegratedHSM=True
```

It takes a few minutes to create the VM and supporting resources.
Once created user should be able to see the tag applied in portal in the tag section.

### Option 2 - ARM Templates

Create a resource group:

```powershell
az group create --name $resourceGroup --location $region
```

Create a VM with the `az deployment group create` command.
Input your resource group name, deployment name and VM name.
Use the [ARM templates provided in this repository](../arm_templates/) to deploy the VM; be sure to input the username and password you wish to use on your VM.

```powershell
az deployment group create `
  -g $resourceGroup `
  -n $deployName `
  -f ./template-azihsm-tvm.json `
  -p ./parameters-azihsm-tvm.json `
  -p vmName=$vmName
```

### Option 3 - Azure SDK

There are many different languages supported by the Azure SDK. For this sample, we will use python.

Navigate to [azure_sdk/python](../azure_sdk/python/) and create a python virtual environment and install the Azure SDK:

```powershell
python -m venv .venv
.venv/Scripts/activate # only required if deploying from a Windows machine
pip install -r requirements.txt
```

Then run the sample script provided. The script includes documentation on what resources are deployed in order to deploy a VM:

```powershell
python ./sample.py
```
