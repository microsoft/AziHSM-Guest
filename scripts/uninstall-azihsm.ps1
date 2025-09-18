# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script uninstalls all AziHSM Windows dependencies.
#
#   1. The AziHSM Device Driver
#   2. The AziHSM KSP DLL
#
# After this script completes, you will no longer be able to use the AziHSM in
# your applications on this machine.

#Requires -RunAsAdministrator
#Requires -Version 5.1

$script:ROOT = "$PSScriptRoot"
$script:PWD = "$pwd"
$script:STATUS_SUCCESS = 0
$script:STATUS_FAIL = -1

$script:AZIHSM_DRIVER_FILES = @( `
    "AziHSMVf.man", `
    "AziHsmVf.cer", `
    "AziHsmVf.pdb", `
    "AziHsmVf.inf", `
    "AziHsmVf.sys", `
    "azihsmvf.cat" `
)

$script:AZIHSM_KSP_FILE_NAME = "azihsmksp.dll"
$script:AZIHSM_KSP_INSTALL_DIR = "$env:SYSTEMROOT\System32"
$script:AZIHSM_KSP_REGISTERED_NAME = "Microsoft Azure Integrated HSM Key Storage Provider"

# Helper function for spawning a progress and waiting for it to complete.
# Returns a Process object on success, and `$null` if launching the process failed.
function run_cmd
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$CmdName,
        [Parameter(Mandatory=$false)]
        [string]$CmdArgs
    )

    # Make sure the command exists
    $cmd_path = Get-Command "$CmdName" | Select-Object -ExpandProperty Path
    if ($cmd_path -eq $null)
    {
        Write-Error "Failed to find command: `"$CmdName`"."
        return $null
    }

    # Launch a subprocess and wait for it to complete
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$cmd_path"
    $pinfo.Arguments = "$CmdArgs"
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $output = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{
        Process = $proc
        Output = $output
    }
}

# Retrieves information on the AziHSM driver, if it is currently registered
# with the OS.
# Returns `$null` if no AziHSM driver is installed.
function get_driver_registration
{
    $result = run_cmd -CmdName "pnputil" -CmdArgs "/enum-drivers"
    $out = $result.Output

    # Read the output line-by-line
    $lines = $out -split "`n"
    $driver_info = $null
    foreach ($line in $lines)
    {
        # Sanitize each line of output
        $line = $line.Trim()
        $line = $line.Replace("`t", " ")

        # Skip lines that don't have key-value pair syntax
        if (-not ($line -match "[a-zA-Z0-9_\-\s]+:"))
        {
            continue
        }

        # Split by the colon to get name/value
        $pieces = $line -split ":"
        if ($pieces.Length -lt 2)
        {
            Write-Error "Unexpected output from pnputil: `"$line`"."
            return $null
        }
        $key = $pieces[0].Trim()
        $val = $pieces[1].Trim()

        # If this line contains the 'Published Name'...
        if ($key -like "*Published Name*")
        {
            # Reset the `driver_info` object
            $driver_info = [PSCustomObject]@{
                PublishedName = $val
                OriginalName = $null
            }
        }

        # If this line contains the 'Original Name'...
        if ($key -like "*Original Name*")
        {
            $driver_info.OriginalName = $val

            # If this is the AziHSM driver, return the `driver_info` object
            $azihsm_driver_inf_name = $script:AZIHSM_DRIVER_FILES | Where-Object { $_ -match '\.inf' }
            if ($val -like "$azihsm_driver_inf_name")
            {
                return $driver_info
            }
        }
    }

    return $null
}

# Main function for uninstalling the AziHSM device driver.
function main_driver
{
    Write-Host "---------------------"
    Write-Host "AziHSM Driver Removal"
    Write-Host "---------------------"

    # Is there a driver currently installed? If not, return early
    $driver_info = get_driver_registration
    if (-not $driver_info)
    {
        Write-Host "AziHSM driver is not currently installed."
        return $script:STATUS_SUCCESS
    }

    Write-Host "Found AziHSM driver; installed as: `"$($driver_info.PublishedName)`"."

    # Delete the driver by invoking `pnputil`
    Write-Host "Uninstalling old AziHSM driver (`"$($driver_info.PublishedName)`")..."
    $pnputil_args = "/delete-driver "
    $pnputil_args = "$pnputil_args `"$($driver_info.PublishedName)`" "
    $pnputil_args = "$pnputil_args /uninstall"
    $result = run_cmd -CmdName "pnputil" -CmdArgs "$pnputil_args"
    if ($result.Process.ExitCode -ne 0)
    {
        $msg = "Failed to uninstall AziHSM driver (`"$($driver_info.PublishedName)`"):`n"
        $msg = "$msg $($result.Output)"
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }
    Write-Host "Uninstalled old AziHSM driver (`"$($driver_info.PublishedName)`") successfully."

    return $script:STATUS_SUCCESS
}

# Returns `$true` if the KSP DLL is registered with the OS as a Key Storage
# Provider (KSP).
function is_ksp_registered
{
    $result = run_cmd -CmdName "certutil" -CmdArgs "-csplist"
    $out = $result.Output

    return $out -like "*$script:AZIHSM_KSP_REGISTERED_NAME*"
}

# Main function for uninstalling the AziHSM KSP DLL.
function main_ksp
{
    Write-Host "------------------"
    Write-Host "AziHSM KSP Removal"
    Write-Host "------------------"

    # Is there an existing AziHSM KSP DLL installed?
    $ksp_install_path = Join-Path -Path "$script:AZIHSM_KSP_INSTALL_DIR" `
                                        -ChildPath "$script:AZIHSM_KSP_FILE_NAME"
    $ksp_exists = Test-Path -Path "$ksp_install_path" -PathType "Leaf"
    if ($ksp_exists)
    {
        Write-Host "AziHSM KSP DLL is currently installed at: `"$ksp_install_path`"."
    }
    else
    {
        Write-Host "AziHSM KSP DLL is not currently installed at: `"$ksp_install_path`"."
    }

    # Is the KSP already registered as a Key Storage Provider? If so, we'll
    # unregister it.
    $ksp_is_registered = is_ksp_registered
    if ($ksp_is_registered)
    {
        Write-Host "AziHSM KSP is currently registered."

        # If the KSP is registered, but we couldn't find the DLL, there seems
        # to have been some sort of issue when installing (the KSP DLL was
        # placed somewhere unexpected).
        if (-not $ksp_exists)
        {
            $msg = "The AziHSM KSP is registered, but the DLL (`"$AZIHSM_KSP_FILE_NAME`") could not be found at: `"$ksp_install_path`"."
            $msg = "$msg Please manually locate the DLL and move it to `"$ksp_install_path`"."
            $msg = "$msg Then, re-run this script to complete the uninstall."
            Write-Error "$msg"
            return $script:STATUS_FAIL
        }

        # Unregister the KSP
        Write-Host "Unregistering the AziHSM KSP..."
        $null = run_cmd -CmdName "regsvr32" -CmdArgs "/s /u `"$ksp_install_path`""

        # Make sure the unregistration succeeded; if it is still registered,
        # then the above command failed.
        if ((is_ksp_registered))
        {
            Write-Error "Failed to unregister the AziHSM KSP DLL at: `"$ksp_install_path`"."
            return $script:STATUS_FAIL
        }
        Write-Host "Unregistered the AziHSM KSP successfully."
    }
    else
    {
        Write-Host "AziHSM KSP is not currently registered."
    }

    # If the KSP DLL file is installed, we'll delete it
    if ($ksp_exists)
    {
        Write-Host "Deleting AziHSM KSP DLL at: `"$ksp_install_path`"..."
        Remove-Item -Path "$ksp_install_path" -Force

        # Make sure the file no longer exists
        if (Test-Path -Path "$ksp_install_path" -PathType "Leaf")
        {
            Write-Error "Failed to delete AziHSM KSP DLL at `"$ksp_install_path`"."
            return $script:STATUS_FAIL
        }
        Write-Host "Deleted AziHSM KSP DLL successfully."
    }

    return $script:STATUS_SUCCESS
}

# Shows the 'help menu' for the script.
function show_help
{
    Write-Host "Uninstall AziHSM Dependencies."
    Write-Host ""
    Write-Host "Available Options:"
    Write-Host "------------------"
    Write-Host "-Help"
    Write-Host "    Shows this help menu."
    Write-Host "-SkipDriver"
    Write-Host "    (OPTIONAL) Skips the removal of the AziHSM driver."
    Write-Host "-SkipKSP"
    Write-Host "    (OPTIONAL) Skips the removal of the AziHSM KSP DLL."
    Write-Host "-SkipSymCrypt"
    Write-Host "    (OPTIONAL) Skips the removal of the SymCrypt DLL."

    return $script:STATUS_SUCCESS
}

# Main function.
function main
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [switch]$Help,
        [Parameter(Mandatory=$false)]
        [switch]$SkipDriver,
        [Parameter(Mandatory=$false)]
        [switch]$SkipKSP,
        [Parameter(Mandatory=$false)]
        [switch]$SkipSymCrypt
    )

    if ($Help)
    {
        return show_help
    }

    # Uninstall the AziHSM KSP DLL
    if (-not $SkipKSP)
    {
        $status = main_ksp
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $status
        }
        Write-Host "SUCCESS: AziHSM KSP has been uninstalled.`n"
    }

    # Uninstall the AziHSM driver
    if (-not $SkipDriver)
    {
        $status = main_driver
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $status
        }
        Write-Host "SUCCESS: AziHSM driver has been uninstalled.`n"
    }

    if ((-not $SkipDriver) -or `
        (-not $SkipKSP))
    {
        Write-Host "Uninstall complete."
    }
    return $script:STATUS_SUCCESS
}

$status = main @args
exit $status

