# Tracing AziHSM Windows Events

The AziHSM guest VM components log debug, informational, and error output through the [ETW (Event Tracing for Windows)](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) system.
This repository contains scripts that can be used to capture this output into a file for debugging purposes.

## AziHSM ETW GUIDs

Each AziHSM component registers its own ETW Provider, which is referred to via a unique GUID:

* **AziHSM Device Driver** GUID: `6f3170cd-d4f0-4e06-8e07-5bcf2f20771c`
* **AziHSM KSP** GUID: `6f3b7e7a-7f98-4fb5-a0ce-e994136df3e2`

## Step 1 - Start a Session

To begin a trace session, execute the [`trace-collect-start.ps1`](../scripts/trace-collect-start.ps1) script on your VM, specifying a unique session name and the GUIDs listed above.
We recommend creating a different trace session for each component:

```powershell
.\trace-collect-start.ps1 -SessionName "AZIHSM_DRIVER_TRACE_1" -ProviderGUIDs "6f3170cd-d4f0-4e06-8e07-5bcf2f20771c" -OutputPath "$env:USERPROFILE\AZIHSM_DRIVER_TRACE_1.etl"
.\trace-collect-start.ps1 -SessionName "AZIHSM_KSP_TRACE_1" -ProviderGUIDs "6f3b7e7a-7f98-4fb5-a0ce-e994136df3e2" -OutputPath "$env:USERPROFILE\AZIHSM_KSP_TRACE_1.etl"
```

Upon completion of the script, the output `.etl` file should be created.

### Step 1a (OPTIONAL) - Set KSP Logging Level

The AziHSM KSP has a level-based logging system, where each log message is assigned a level.
These levels are: `ERROR`, `WARN`, `INFO`, `DEBUG`.
By default, error, warning, and info messages will be logged; debug messages will *not* be logged.
However, if you need more information, you can set the `AZIHSMKSP_LOG_LEVEL` environment variable to one of the following values:

```powershell
# Enable debug log messages
$env:AZIHSMKSP_LOG_LEVEL = "DEBUG"

# Set back to default
$env:AZIHSMKSP_LOG_LEVEL = $null
$env:AZIHSMKSP_LOG_LEVEL = "INFO"
```

## Step 2 - Reproduce the Issue

With the tracing sessions active, reproduce the issue you would like to debug.
Log messages will be automatically captured into the output `.etl` files.

## Step 3 - Stop the Session

Once you are finished reproducing the issue, stop the existing trace sessions by executing the [`trace-collect-stop.ps1`](../scripts/trace-collect-stop.ps1) script on your VM.
Specify the same session name as you did when you started tracing:

```powershell
.\trace-collect-stop.ps1 -SessionName "AZIHSM_DRIVER_TRACE_1"
.\trace-collect-stop.ps1 -SessionName "AZIHSM_KSP_TRACE_1"
```

## Step 4 - Convert the ETL File

This step is optional, but useful for converting the events within the `.etl` file into a more useful and/or friendly format.
Execute the [`trace-convert.ps1`](../scripts/trace-convert.ps1) script on your VM, and point it to the output `.etl` file that was produced in the steps above.

```powershell
# Convert to CSV:
.\trace-convert.ps1 -ETLFilePath "$env:USERPROFILE\AZIHSM_DRIVER_TRACE_1.etl" -OutputFormat "CSV"
.\trace-convert.ps1 -ETLFilePath "$env:USERPROFILE\AZIHSM_KSP_TRACE_1.etl" -OutputFormat "CSV"

# Convert to TXT:
.\trace-convert.ps1 -ETLFilePath "$env:USERPROFILE\AZIHSM_DRIVER_TRACE_1.etl" -OutputFormat "TXT"
.\trace-convert.ps1 -ETLFilePath "$env:USERPROFILE\AZIHSM_KSP_TRACE_1.etl" -OutputFormat "TXT"

# Convert to XML:
.\trace-convert.ps1 -ETLFilePath "$env:USERPROFILE\AZIHSM_DRIVER_TRACE_1.etl" -OutputFormat "XML"
.\trace-convert.ps1 -ETLFilePath "$env:USERPROFILE\AZIHSM_KSP_TRACE_1.etl" -OutputFormat "XML"

```

