# Secure Key Release sample

This sample will demonstrate the Secure Key Release flow for AziHSM.

Secure Key Release for AziHSM allows a user to securely import keys from Azure Key Vault into AziHSM, attested by MAA.

## Prerequisites

In addition to the prerequisites in the [top-level README.md](../README.md), you will need to set up additional Azure resources, as well as installing the specific software library that enables Secure Key Release.

### Azure resources

This Secure Key Release sample involves the following Azure resources:

1. [Microsoft Azure Attestation](https://marketplace.microsoft.com/en-us/product/microsoft.Free?tab=Overview)
2. [Azure Key Vault](https://marketplace.microsoft.com/en-us/product/Microsoft.KeyVault?tab=Overview), sku: Premium
3. Azure VM with Trusted Launch and AziHSM enabled

#### Create Microsoft Azure Attestation

> A custom MAA endpoint is required  
> AziHSM Attestation is only enabled in custom endpoint  
> As this allows customers to define custom policy  
> A baseline policy is provided by default

The Microsoft Azure Attestation will aid attestation of AziHSM's import key, and produce a JSON Web Token so Azure Key Vault could release a key.

Azure CLI is required. You can either open a cloud shell on portal.azure.com, or [install Azure CLI](https://learn.microsoft.com/en-us/cli/azure/?view=azure-cli-latest).

Next, create the MAA endpoint resource:

```
az attestation create --name <your MAA name> --resource-group <your resource group> --location <pick a region like eastus>
```

Once created, obtain the Attest URI of the Attestation provider.

#### Create Azure Key Vault

The Azure Key Vault will store keys, so later we could release these keys into an AziHSM enabled VM.

First, create an Azure Key Vault with the Premium SKU, which enables HSM-protected keys.

```
az keyvault create --name <your resource name> --resource-group <your resource group> --enable-rbac-authorization true --sku premium
```

**Setup access to AKV**

AKV uses role-based access control (RBAC), by default your account won't have any role.

> https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli

You should have a role that allows you to create keys on this Azure Key Vault.
For the rest of this sample, use the role "Key Vault Crypto Officer". You should set it up using:

```
az role assignment create --role "Key Vault Crypto Officer" --assignee <your account@mail.com> --scope /subscriptions/<subscriptionid>/resourcegroups/<resource-group-name>/providers/Microsoft.KeyVault/vaults/<key-vault-name>
```

Next, for this sample we will create one RSA 2k key in Azure Key Vault.

```
az keyvault key create --exportable true --vault-name <your akv name> --kty RSA-HSM --size 2048 --name <key name> --policy skr-policy.json
```

You will need to create the `skr-policy.json`.
It should have the following content (replace `authority` with the "Attest URI" of the created MAA endpoint).

> For more information, see [Secure Key Release feature with AKV](https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation)

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

Once the key is created, obtain its Key Identifier, like
`https://<AKV name>.vault.azure.net/keys/<key name>/<version>`

#### Create VM

Please follow [HowToDeploy.md](../../../docs/HowToDeploy.md).

**Setup access to Azure Key Vault**

To access the AKV, the VM needs a proper role, just like your dev account.
There are multiple approaches to access control. See https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal

In this sample let's also assign the role "Key Vault Crypto Officer" to your VM.

```powershell
az role assignment create --role "Key Vault Crypto Officer" --assignee <VM Object (principal) ID> --scope /subscriptions/<subscriptionid>/resourcegroups/<resource-group-name>/providers/Microsoft.KeyVault/vaults/<key-vault-name>
```

> You can find the VM Object (principal) ID on the Azure Portal.
> Go to the VM page, select tab "Security" > "Identity" > "Object (principal) ID"
>
> Or use Azure CLI
> `az vm show --name <VM Name> --resource-group <VM Resource Group> --query identity.principalId`

### Setup software dependency on VM

**AziHSM driver**

This step is optional as the VM should be created with the proper driver and dependencies (NCrypt, SymCrypt, etc).

To verify this, you can obtain and run [get_device_info.exe](https://github.com/microsoft/AziHSM-Guest/releases/tag/get_device_info%2Fv0.1.0)

You should see output similar to this:

```
====Start Logging AziHSM device information
Device PCI info: "MCR:XXXXXXXX:Y:Z"
AziHSM VF driver version: "X.X.XXX.X"
AziHSM FW ver: "X.Y.ZZZZZZZZ"
AziHSM HW ver: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
====Done Logging AziHSM device information
```

**Sample dependency**

To run this sample, we need:
1. Install the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (or a newer SDK that can target `net8.0`)
2. Install the [Microsoft Visual C++ Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe)
3. Restore the NuGet dependencies:
    1. `cd SECURE-KEY-RELEASE\`
    2. `dotnet restore`

This project depends on the following packages:

| Package | Purpose |
|---|---|
| `Microsoft.Azure.Security.GuestAttestation` | The Guest Attestation Library (`AttestationClientLib.dll`) |
| `Azure.Identity` | Authenticates to Azure Key Vault using the VM's managed identity |
| `Azure.Security.KeyVault.Keys` | Calls the Azure Key Vault key release API |

The project file copies `AttestationClientLib.dll` into the output directory, so the built executable is ready to run.

> **Why the Visual C++ Redistributable?** The Guest Attestation Library is native and depends on the
> Visual C++ runtime, which is not present on a clean Windows Server image. Without it the sample
> fails with `Unable to load DLL 'AttestationClientLib' or one of its dependencies (0x8007007E)` —
> note that `AttestationClientLib.dll` itself *is* in the output directory; it is the dependency that
> is missing.

## How to run sample

> See top-level [README.md](../README.md) for prerequisites.

The sample takes 3 command line arguments:

```
Usage: SECURE-KEY-RELEASE.exe <MAA_ENDPOINT> <KEY_URL> [CLIENT_ID]
```

`<MAA_ENDPOINT>` and `<KEY_URL>` are URLs from the Azure resources we created earlier.

`[CLIENT_ID]` is an optional string, representing the Client ID of an Azure Identity. That identity should have the proper AKV role. Use this if there are multiple Azure identities attached to a VM.
> If you created the VM following this guide then you don't need to give a client id.

```powershell
dotnet run --project SECURE-KEY-RELEASE -c Release -- `
    https://<your MAA endpoint>.attest.azure.net `
    https://<AKV name>.vault.azure.net/keys/<key name>/<version>
```

Output of the sample code:

```
<...>
Done attest_import_key.
Done release_key. wrapped key blob length: 1488. Key type: RSA. Key size: 2048
Done import_key_blob
Done secure_key_release
Signature size: 256 bytes.
Signature internally verified successfully.
Done test workload.
Done test_imported_key
```

## Re-use the sample code

If you wish to re-use the sample's Secure Key Release related code, please review the `SecureKeyReleaseFlow.Run` method in [SecureKeyReleaseFlow.cs](./SecureKeyReleaseFlow.cs).

Please note there are several skipped or simplified pieces of logic for demo purposes. Replace them with a proper implementation for your workload:

1. `GenerateNonce`: the sample uses a fixed nonce; please use a random nonce.
2. `ParseAkvJwt`: the sample skips verification of the JWT; please perform verification using a proper JWT library, such as [`Microsoft.IdentityModel.JsonWebTokens`](https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens).

### Guest Attestation Library

Link: https://www.nuget.org/packages/Microsoft.Azure.Security.GuestAttestation

This library is necessary for Secure Key Release as it performs AziHSM import key attestation:

- Collect security reports and measurements from the host environment and AziHSM device
- Communicate with the Microsoft Azure Attestation (MAA) endpoint for key attestation
- Verify and return MAA tokens required for the Azure Key Vault key release API

It comes as a NuGet Package that exposes a C API, which [AttestationClient.cs](./AttestationClient.cs) wraps.

Note that `AttestAziHsm` allocates the attestation token buffer, so the caller must release it with the library's own `Free` function once finished with it.

When redistributing code that uses this library, remember to include `AttestationClientLib.dll`.

### Accessing Azure Key Vault

Obtaining an access token and calling the key release API are both handled by the Azure SDK:

```csharp
KeyVaultKeyIdentifier keyIdentifier = new(new Uri(keyUrl));

DefaultAzureCredentialOptions credentialOptions = new();
if (!string.IsNullOrEmpty(clientId))
{
    credentialOptions.ManagedIdentityClientId = clientId;
}

KeyClient keyClient = new(keyIdentifier.VaultUri, new DefaultAzureCredential(credentialOptions));

ReleaseKeyOptions options = new(keyIdentifier.Name, maaToken)
{
    Version = keyIdentifier.Version,
    Nonce = GenerateNonce(),
    Algorithm = KeyExportEncryptionAlgorithm.CkmRsaAesKeyWrap,
};

ReleaseKeyResult result = keyClient.ReleaseKey(options);
```

`DefaultAzureCredential` obtains the access token from the VM's managed identity through the [Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service), including retries and caching. `ManagedIdentityClientId` selects a specific user-assigned identity, which corresponds to the optional `CLIENT_ID` argument.

### Assembling the import blob

Azure Key Vault returns the raw PKCS#11 `CKM_RSA_AES_KEY_WRAP` payload inside a JWT. AziHSM expects that payload behind a PKCS#11 wrapped key blob header, so the sample prepends one before importing. AKV wraps with OAEP over SHA-1, so that is the padding algorithm identifier written into the header:

```csharp
byte[] fullBlob = RsaWrapUtils.BuildPkcs11WrapBlob(released.KeyBlob, NCryptConstants.NCRYPT_SHA1_ALGORITHM);

NCryptKeyHandle importedKey = CryptoUtils.ImportWrappedKey(
    provider, importKey, fullBlob, released.KeyType, released.KeySize, keyUsage);
```
