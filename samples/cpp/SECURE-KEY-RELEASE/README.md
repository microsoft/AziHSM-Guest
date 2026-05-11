# Secure Key Release sample

This sample will demonstrate the Secure Key Release flow for AziHSM.

Secure Key Release for AziHSM allows user to securely import keys from Azure Key Vault into AziHSM, attested by MAA.

## Prerequisites

In additional to prerequisites from top-level README.md, you will need to setup additional Azure resources, as well as installing specific software library that enables Secure Key Release.

### Azure resources
This Secure Key Release sample involves following Azure resources:

1. [Microsoft Azure Attestation](https://marketplace.microsoft.com/en-us/product/microsoft.Free?tab=Overview)
2. [Azure Key Vault](https://marketplace.microsoft.com/en-us/product/Microsoft.KeyVault?tab=Overview), sku: Premium
3. Azure VM with Trusted Launch and AziHSM enabled

#### Create Microsoft Azure Attestation

The Microsoft Azure Attestation will aid attestation of AziHSM's import key, and produce a JSON Web Token so Azure Key Vault could release a key.

> Install Azure CLI  
> https://learn.microsoft.com/en-us/cli/azure/?view=azure-cli-latest

```
az attestation create --name <your MAA name> --resource-group <your resource group> --location <pick a region like eastus>
```

Note the Attest URI of the created Attestatoin provider.

#### Create Azure Key Vault

The Azure Key Vault will store keys, so later we could release these keys into AziHSM enabled VM.

First, create Azure Key Vault with Premium SKU, which enables HSM-protected keys.
```
az keyvault create --name <your resource name> --resource-group <your resource group> --enable-rbac-authorization true --sku premium
```

> Setup access before proceeding  
> https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli  
> You should have role that allows you to create keys on this Azure Key Vault  
> For the rest of this sample, assuming you have role "Key Vault Crypto Officer"  
> Example: `az role assignment create --role "Key Vault Crypto Officer" --assignee <xxx@mail.com> --scope /subscriptions/<subscriptionid>/resourcegroups/<resource-group-name>/providers/Microsoft.KeyVault/vaults/<key-vault-name>`

Next, for this sample we will create one RSA 2k key in Azure Key Vault.
```
az keyvault key create --exportable true --vault-name <your akv name> --kty RSA-HSM --size 2048 --name <key name> --policy skr-policy.json
```

Example content of `skr-policy.json`
> For more information, see [Secure Key Release feature with AKV ](https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation)

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://<your MAA endpoint>.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-attestation-type",
          "equals": "aihsm"
        },
        {
           "claim": "x-ms-aihsm-azurevm-binding-status",
           "equals": "attached"
        },
        {
           "claim": "x-ms-compliance-status",
           "equals": "azure-compliant-aihsm"
        }
      ]
    }
  ]
}
```

Obtain the Key Identifier of this key, like  
`https://<AKV name>.vault.azure.net/keys/<key name>/<version>`

#### Create VM

Please follow [HowToDeploy.md](../../docs/HowToDeploy.md)

**Setup access to Azure Key Vault**

After creating the VM, assign proper role to VM to allow it to access the created Azure Key Vault.  
There are multiple approaches to access control. See https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal  

In this example let's assign role "Key Vault Crypto Officer" from the Azure Key Vault to your VM.

```powershell
az role assignment create --role "Key Vault Crypto Officer" --assignee <VM Object ID> --scope /subscriptions/<subscriptionid>/resourcegroups/<resource-group-name>/providers/Microsoft.KeyVault/vaults/<key-vault-name>
```

### Setup software dependency on VM

If setup correctly, the VM should have AziHSM related drivers and dependencies (NCrypt, SymCrypt, etc) pre-installed. To verify this, you can obtain and run [get_device_info.exe](https://github.com/microsoft/AziHSM-Guest/releases/tag/get_device_info%2Fv0.1.0)

You should see output similar to this
```
====Start Logging AziHSM device information
Device PCI info: "MCR:XXXXXXXX:Y:Z"
AziHSM VF driver version: "X.X.XXX.X"
AziHSM FW ver: "X.Y.ZZZZZZZZ"
AziHSM HW ver: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
====Done Logging AziHSM device information
```

Additionally, We need to setup following software dependencies:
1. Install Visual Studio 2019 or newer
2. Install vcpkg for Visual Studio: https://learn.microsoft.com/en-us/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell
3. Install vcpkg dependencies: `vcpkg install`.
    1. This project uses vcpkg manifest mode, see [vcpkg.json](./vcpkg.json)

## How to run

> See top-level [README.md](../README.md) for prerequisites.

The sample takes 3 command line arguments:
```
Usage: SECURE-KEY-RELEASE.exe <MAA_ENDPOINT> <KEY_URL> [CLIENT_ID]
```

`<MAA_ENDPOINT>` and `<KEY_URL>` are URLs from Azure resources we created eariler.  
`[CLIENT_ID]` is an optional string, representing the Client ID of an Azure Identity, this identity should have role to assign keys in the created Azure Key Vault.
> If you followed this guide then you don't need to give a client id, as this VM has proper access.

Output of the sample code
```
<...>
Done attest_import_key.
Done release_key. wrapped key blob length: 1488
Done import_wrapped_key
Done secure_key_release
Encryption successful. Ciphertext length: 256
Encrypt-decrypt test passed!
Done test_imported_key
```

## Re-use the sample code

If you wish to re-use the sample's Secure Key Release related code, please review `secure_key_release` function.

Please note there are several skipped or simplified logic for demo purpose, please replace them with proper implementation for your workload:
1. `generate_nonce`: in the sample a fixed nonce is used, please use random nonce.
2. `parse_akv_jwt`: in the sample verification of JWT is skipped, please perform verification using proper crypto library.

You will also need to install Guest Attestation Library that is needed for SKR, in addition to existing AziHSM lib (`azihsmksp.dll`).

### Guest Attestation Library

Link: https://www.nuget.org/packages/Microsoft.Azure.Security.GuestAttestation

This library is necessary for Secure Key Release as it performs AziHSM import key attestation:
- Collect security reports and measurements from the host environment and AziHSM device
- Communicate with the Microsoft Azure Attestation (MAA) endpoint for key attestation
- Verify and return MAA tokens required for Azure Key Vault key release API

It comes as a NuGet Package, to use, simply add it to your Visual Studio project and include its header file

```c
#include <AziHSMAttestationApi.h>
```

You can also check this sample code on how to use this library.

When redistributing code that uses this library, remember to include `AttestationClientLib.dll`.
