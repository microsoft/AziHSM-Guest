# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script installs all necessary Windows dependencies for the AziHSM.
#
#   1. The AziHSM Device Driver
#   2. The AziHSM KSP DLL
#   3. The SymCrypt DLL (a dependency of the KSP DLL)
#
# Please execute this script to ensure all dependencies are installed before
# attempting to use the AziHSM in your applications.

#Requires -RunAsAdministrator
#Requires -Version 5.1

$script:ROOT = "$PSScriptRoot"
$script:PWD = "$pwd"
$script:STATUS_SUCCESS = 0
$script:STATUS_FAIL = -1

$script:HARDWARE = "amd64"

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

$script:SYMCRYPT_FILE_NAME = "symcrypt.dll"
$script:SYMCRYPT_INSTALL_DIR = "$env:SYSTEMROOT\System32"
$script:SYMCRYPT_REPO_OWNER = "microsoft"
$script:SYMCRYPT_REPO_NAME = "SymCrypt"
$script:SYMCRYPT_REPO_RELEASE = "v103.8.0"

# Helper function for spawning a process and waiting for it to complete.
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

# Helper function that pings a GitHub endpoint and returns a list of file names
# (assets) that can be downloaded from a GitHub release.
function query_github_release_files
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$RepoOwner,
        [Parameter(Mandatory=$true)]
        [string]$RepoName,
        [Parameter(Mandatory=$true)]
        [string]$ReleaseTag
    )

    # Build a GitHub URL with the provided parameters
    $url = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/tags/$ReleaseTag"

    # Build headers and send a HTTP request to the URL
    $headers = @{
        "Accept" = "application/json"
    }
    $response = Invoke-RestMethod -Uri "$url" -Headers $headers

    # Get the asset URL and query it; return the result (a list of objects
    # describing each asset)
    $asset_url = $response.assets_url
    $response = Invoke-RestMethod -Uri "$asset_url" -Headers $headers
    return $response
}

# Function that expands the provided `.zip` or `.nuget` archive.
# Returns a status code indicating success or failure.
function expand_archive
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    # If the destination path already exists, don't proceed any further
    if (Test-Path -Path "$DestinationPath" -PathType "Container")
    {
        $msg = "The destination path (`"$DestinationPath`") already exists."
        $msg = "$msg Skipping expansion of archive `"$Path`"."
        Write-Warning "$msg"
        return $script:STATUS_FAIL
    }

    # Is the archive a NuGet package (`.nupkg`)? If so, we need to temporarily
    # rename it to be `.zip`, so it can be processed by the `Expand-Archive`
    # function. (NuGet packages are zip archives.)
    $path_new = "$Path"
    $ext_old = [System.IO.Path]::GetExtension("$path_new")
    $ext_new = $null
    if ($ext_old.ToLower() -eq ".nupkg")
    {
        $ext_new = ".zip"
        $path_new = [System.IO.Path]::ChangeExtension("$path_new", "$ext_new")
        Move-Item -Path "$Path" -Destination "$path_new"
        Write-Host "Temporarily renamed archive `"$Path`" to: `"$path_new`"."
    }

    # Otherwise, expand the archive
    Expand-Archive -Path "$path_new" -DestinationPath "$DestinationPath"

    # Make sure the expanded directory was created
    if (-not (Test-Path -Path "$DestinationPath" -PathType "Container"))
    {
        $msg = "Failed to expand archive `"$path_new`"."
        $msg = "$msg Destination directory `"$DestinationPath`" could not be found."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Change the archive's extension back to its original extension, if
    # applicable
    if ($ext_new -ne $null)
    {
        [System.IO.Path]::ChangeExtension("$path_new", "$ext_old")
        Move-Item -Path "$path_new" -Destination "$Path"
        Write-Host "Restored archive's original name (from: `"$Path`" to: `"$path_new`")."
    }

    return $script:STATUS_SUCCESS
}

# Examines the given file path and ensures it points to a directory containing
# all needed driver files. Returns a value indicating a successful (or failed)
# verification.
function verify_driver_files
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Make sure the given path exists as a directory
    if (-not (Test-Path -Path "$Path" -PathType "Container"))
    {
        return $script:STATUS_FAIL
    }

    # Iterate through all driver files, and ensure they are present in the
    # directory.
    foreach ($filename in $script:AZIHSM_DRIVER_FILES)
    {
        $filepath = Join-Path -Path "$Path" -ChildPath "$filename"
        if (-not (Test-Path -Path "$filepath" -PathType "Leaf"))
        {
            Write-Warning "Directory `"$Path`" does not contain needed driver file: `"$filename`"."
            return $script:STATUS_FAIL
        }
    }

    return $script:STATUS_SUCCESS
}

# Helper function that looks for AziHSM driver `.zip` or `.nupkg` archives.
# All found paths are returned in a list.
# If none are found, an empty list is returned.
function find_driver_archives
{
    $result = @()

    # Search the working directory for driver archives
    $paths = @(Get-ChildItem -Path "$script:PWD" -Recurse | Where-Object { `
        ($_.Extension -in ".zip", ".nupkg") `
        -and ($_.Name -like "*azihsm*") `
        -and ($_.Name -like "*driver*") `
    })
    $paths_len = $paths.Length
    if ($paths_len -ge 1)
    {
        $msg = "Found $paths_len AziHSM Driver archive(s):"
        foreach ($path in $paths)
        {
            $result += @("$($path.FullName)")
            $msg = "$msg `"$($path.FullName)`""
        }
        Write-Host "$msg"
    }

    if ($result.Length -eq 0)
    {
        Write-Host "Found no AziHSM Driver archives in: `"$script:PWD`"."
    }

    return $result
}

# Helper function that looks for the AziHSM driver files in the working
# directory.
# The path to the first-found directory containing *all* driver files is
# returned.
# If none are found, `$null` is returned.
function find_driver
{
    # Iterate through all driver files and build a list of directories that
    # contain at least one driver file.
    $dirs = @()
    foreach ($filename in $script:AZIHSM_DRIVER_FILES)
    {
        # Find all locations for this file
        $paths = @(Get-ChildItem -Path "$script:PWD" -Filter "$filename" -Recurse)
        $paths_len = $paths.Length

        # Iterate through each, determine the directory path, and add it to the
        # list of directories to search
        foreach ($path in $paths)
        {
            $dirname = [System.IO.Path]::GetDirectoryName($path.FullName)
            if (-not ($dirs -contains "$dirname"))
            {
                $dirs += @("$dirname")
                Write-Host "Found directory containing AziHSM driver files: `"$dirname`"."
            }
        }
    }

    # If at least one directory was found, return the first one
    if ($dirs.Length -gt 0)
    {
        $result = $dirs[0]
        Write-Host "Selecting AziHSM driver file directory: `"$result`"."
        return $result
    }

    # If no driver files were found, report and return null
    Write-Warning "Found no AziHSM driver files within: `"$script:PWD`"."
    return $null
}

# Helper function that downloads the AziHSM driver files.
function download_driver
{
    Write-Warning "TODO: Download driver files from GitHub"
    # TODO

    return $null
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

# Main function for installing the AziHSM device driver.
function main_driver
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$Path=$null
    )

    Write-Host "--------------------------"
    Write-Host "AziHSM Driver Installation"
    Write-Host "--------------------------"

    $path = $Path

    # Look for any existing driver archives locally
    if (-not $Path)
    {
        $archives = find_driver_archives

        foreach ($arch in $archives)
        {
            # Create a directory path at which we'll expand the archive
            $arch_obj = Get-Item "$arch"
            $arch_noextension = $arch_obj.BaseName
            $arch_dir = $arch_obj.DirectoryName
            $arch_dest = Join-Path -Path "$arch_dir" -ChildPath "${arch_noextension}_EXPANDED"

            # Expand the archive
            $expand_result = expand_archive -Path "$arch" -DestinationPath "$arch_dest"
            if ($expand_result -eq $script:STATUS_SUCCESS)
            {
                Write-Host "Expanded archive `"$arch`" to destination: `"$arch_dest`"."
            }
        }
    }

    # Was a driver path specified? If not, search for the files locally
    if (-not $path)
    {
        $path = find_driver
    }

    # If the driver wasn't found locally, try to download from GitHub
    if (-not $path)
    {
        $path = download_driver
    }

    # If we still have no driver file path, give up and throw an error.
    if (-not $path)
    {
        $msg = "Failed to find or download the AziHSM driver files."
        $msg = "$msg Please download them manually and place all driver files within a directory, under the same directory as this script."
        $msg = "$msg Then, re-run this script to install it."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Verify the driver files
    $path = (Resolve-Path "$path").Path
    if ((verify_driver_files -Path "$path") -ne $script:STATUS_SUCCESS)
    {
        $msg = "The path (`"$path`") does not contain all (or any) AziHSM KSP driver files."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Is there a driver currently installed?
    $driver_info = get_driver_registration
    if ($driver_info)
    {
        Write-Host "AziHSM driver is already installed as: `"$($driver_info.PublishedName)`"."

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
    }

    # Get the full path to the driver INF file
    $driver_inf_name = $script:AZIHSM_DRIVER_FILES | Where-Object { $_ -match '\.inf' }
    $driver_inf_path = Join-Path -Path "$path" -ChildPath "$driver_inf_name"

    # Install the new driver
    Write-Host "Installing new AziHSM driver (`"$driver_inf_path`")..."
    $pnputil_args = "/install /add-driver `"$driver_inf_path`""
    $result = run_cmd -CmdName "pnputil" -CmdArgs "$pnputil_args"
    if ($result.Process.ExitCode -ne 0)
    {
        $msg = "Failed to install new AziHSM driver (`"$driver_inf_path`"):`n"
        $msg = "$msg $($result.Output)"
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Verify that the new driver is installed
    $driver_info = get_driver_registration
    if (-not $driver_info)
    {
        $msg = "Failed to install new AziHSM driver (`"$driver_inf_path`")."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }
    Write-Host "Installed new AziHSM driver (`"$driver_inf_path`") successfully as: (`"$($driver_info.PublishedName)`")."

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

# Examines the given file path and ensures it points to a valid KSP DLL binary
# file. Returns a value indicating a successful (or failed) verification.
function verify_ksp_file
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Make sure the basename of the path matches the expected KSP DLL name
    $basename = [System.IO.Path]::GetFileName("$Path")
    if ($basename -ne $script:AZIHSM_KSP_FILE_NAME)
    {
        return $script:STATUS_FAIL
    }

    # Make sure the path exists as a file
    if (-not (Test-Path -Path "$Path" -PathType "Leaf"))
    {
        return $script:STATUS_FAIL
    }

    return $script:STATUS_SUCCESS
}

# Helper function that looks for AziHSM KSP `.zip` or `.nupkg` archives.
# All found paths are returned in a list.
# If none are found, an empty list is returned.
function find_ksp_archives
{
    $result = @()

    # Search the working directory for KSP archives
    $paths = @(Get-ChildItem -Path "$script:PWD" -Recurse | Where-Object { `
        ($_.Extension -in ".zip", ".nupkg") `
        -and ($_.Name -like "*azihsm*") `
        -and ($_.Name -like "*ksp*") `
    })
    $paths_len = $paths.Length
    if ($paths_len -ge 1)
    {
        $msg = "Found $paths_len AziHSM KSP archive(s):"
        foreach ($path in $paths)
        {
            $result += @("$($path.FullName)")
            $msg = "$msg `"$($path.FullName)`""
        }
        Write-Host "$msg"
    }

    if ($result.Length -eq 0)
    {
        Write-Host "Found no AziHSM KSP archives in: `"$script:PWD`"."
    }

    return $result
}

# Helper function that looks for a KSP binary in the working directory.
# If multiple are found, the path to the first-found DLL is returned.
# If no KSP DLL is found, `$null` is returned.
function find_ksp
{
    # Search the working directory for the KSP DLL
    $paths = @(Get-ChildItem -Path "$script:PWD" -Filter "$script:AZIHSM_KSP_FILE_NAME" -Recurse)
    $paths_len = $paths.Length
    if ($paths_len -ge 1)
    {
        $msg = "Found $paths_len AziHSM KSP DLL(s):"
        foreach ($path in $paths)
        {
            $msg = "$msg `"$($path.FullName)`""
        }
        Write-Host "$msg"

        # Grab the first result and return its path
        $result = $paths[0].FullName
        Write-Host "Selecting AziHSM KSP DLL at: `"$result`"."
        return $result
    }

    # If no KSP DLL was found, report and return null
    Write-Warning "Found no AziHSM KSP DLL within: `"$script:PWD`"."
    return $null
}

# Helper function that downloads the AziHSM KSP DLL.
function download_ksp
{
    Write-Warning "TODO: Download KSP DLL from GitHub"
    # TODO

    return $null
}

# Main function for installing the AziHSM KSP DLL.
function main_ksp
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$Path=$null
    )

    Write-Host "-----------------------"
    Write-Host "AziHSM KSP Installation"
    Write-Host "-----------------------"

    $path = $Path

    # Look for any existing KSP archives locally
    if (-not $Path)
    {
        $archives = find_ksp_archives

        foreach ($arch in $archives)
        {
            # Create a directory path at which we'll expand the archive
            $arch_obj = Get-Item "$arch"
            $arch_noextension = $arch_obj.BaseName
            $arch_dir = $arch_obj.DirectoryName
            $arch_dest = Join-Path -Path "$arch_dir" -ChildPath "${arch_noextension}_EXPANDED"

            # Expand the archive
            $expand_result = expand_archive -Path "$arch" -DestinationPath "$arch_dest"
            if ($expand_result -eq $script:STATUS_SUCCESS)
            {
                Write-Host "Expanded archive `"$arch`" to destination: `"$arch_dest`"."
            }
        }
    }

    # Was a KSP path specified? If not, search for the KSP DLL locally
    if (-not $path)
    {
        $path = find_ksp
    }

    # If the KSP wasn't found locally, try to download from GitHub
    if (-not $path)
    {
        $path = download_ksp
    }

    # If we still have no KSP path, give up and throw an error.
    if (-not $path)
    {
        $msg = "Failed to find or download the AziHSM KSP DLL."
        $msg = "$msg Please download the DLL manually and place it in the same directory as this script."
        $msg = "$msg Then, re-run this script to install it."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Verify the KSP path
    $path_resolution = Resolve-Path "$path"
    $path = $path_resolution.Path
    if ((verify_ksp_file -Path "$path") -ne $script:STATUS_SUCCESS)
    {
        $msg = "The path (`"$path`") does not point to a valid AziHSM KSP DLL file."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Is the KSP already registered as a Key Storage Provider?
    $ksp_is_registered = is_ksp_registered
    if ($ksp_is_registered)
    {
        Write-Host "AziHSM KSP is already registered."
    }

    # Is there an existing AziHSM KSP DLL installed?
    $ksp_install_path = Join-Path -Path "$script:AZIHSM_KSP_INSTALL_DIR" `
                                        -ChildPath "$script:AZIHSM_KSP_FILE_NAME"
    $ksp_exists = Test-Path -Path "$ksp_install_path" -PathType "Leaf"
    if ($ksp_exists)
    {
        Write-Host "AziHSM KSP DLL is already installed at: `"$ksp_install_path`"."
    }

    # If the KSP is registered...
    if ($ksp_is_registered)
    {
        # If we can't find the DLL, then somehow the DLL was installed
        # somewhere else and was then registered.
        if (-not $ksp_exists)
        {
            $msg = "The AziHSM KSP is already registered, but the old DLL could not be found."
            $msg = "$msg Please relocate the current `"$script:AZIHSM_KSP_FILE_NAME`" to `"$ksp_install_path`" and re-run this script."
            return $script:STATUS_FAIL
        }

        # Otherwise, unregister the KSP with `regsvr32`
        Write-Host "Unregistering the old AziHSM KSP..."
        $null = run_cmd -CmdName "regsvr32" -CmdArgs "/s /u `"$ksp_install_path`""

        # Make sure the unregistration succeeded; if it is still registered,
        # then the above command failed.
        if ((is_ksp_registered))
        {
            Write-Error "Failed to unregister the old AziHSM KSP DLL at: `"$ksp_install_path`"."
            return $script:STATUS_FAIL
        }
        Write-Host "Unregistered the old AziHSM KSP successfully."
    }

    # If an old copy of the KSP already exists...
    if ($ksp_exists)
    {
        # Remove the old file; we're about to install a new one
        Write-Host "Deleting old AziHSM KSP DLL at `"$ksp_install_path`"..."
        Remove-Item -Path "$ksp_install_path" -Force

        # Make sure the file no longer exists
        if (Test-Path -Path "$ksp_install_path" -PathType "Leaf")
        {
            Write-Error "Failed to delete old AziHSM KSP DLL at `"$ksp_install_path`"."
            return $script:STATUS_FAIL
        }
        Write-Host "Deleted the old AziHSM KSP successfully."
    }

    # Copy the new KSP DLL file into the proper place
    Write-Host "Copying new AziHSM KSP DLL from `"$path`" to `"$ksp_install_path`"..."
    Copy-Item -Path "$path" -Destination "$ksp_install_path" -Force

    # Make sure the file was copied
    if (-not (Test-Path -Path "$ksp_install_path" -PathType "Leaf"))
    {
        Write-Error "Failed to copy new AziHSM KSP DLL from `"$path`" to `"$ksp_install_path`"."
        return $script:STATUS_FAIL
    }
    Write-Host "Copied new AziHSM KSP DLL successfully."

    # Register the new KSP
    Write-Host "Registering new AziHSM KSP DLL at: `"$ksp_install_path`"..."
    $null = run_cmd -CmdName "regsvr32" -CmdArgs "/s `"$ksp_install_path`""

    # Make sure the new KSP is registered
    $ksp_is_registered = is_ksp_registered
    if (-not $ksp_is_registered)
    {
        $msg = "Failed to register new AziHSM KSP DLL at: `"$ksp_install_path`"."
        $msg = "$msg Please run ``regsvr32 `"$ksp_install_path`"`` manually to debug."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }
    Write-Host "Registered new AziHSM KSP DLL successfully."

    return $script:STATUS_SUCCESS
}

# Examines the given file path and ensures it points to a valid SymCrypt DLL
# binary file. Returns a value indicating a successful (or failed)
# verification.
function verify_symcrypt_file
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Make sure the basename of the path matches the expected SymCrypt DLL name
    $basename = [System.IO.Path]::GetFileName("$Path")
    if ($basename -ne $script:SYMCRYPT_FILE_NAME)
    {
        return $script:STATUS_FAIL
    }

    # Make sure the path exists as a file
    if (-not (Test-Path -Path "$Path" -PathType "Leaf"))
    {
        return $script:STATUS_FAIL
    }

    return $script:STATUS_SUCCESS
}

# Helper function that looks for a SymCrypt DLL in the working directory.
# If multiple are found, the path to the first-found DLL is returned.
# If no SymCrypt DLL is found, `$null` is returned.
function find_symcrypt
{
    # Search the working directory for the KSP DLL
    $paths = @(Get-ChildItem -Path "$script:PWD" -Filter "$script:SYMCRYPT_FILE_NAME" -Recurse)
    $paths_len = $paths.Length
    if ($paths_len -ge 1)
    {
        $msg = "Found $paths_len SymCrypt DLL(s):"
        foreach ($path in $paths)
        {
            $msg = "$msg `"$($path.FullName)`""
        }
        Write-Host "$msg"

        # Grab the first result and return its path
        $result = $paths[0].FullName
        Write-Host "Selecting SymCrypt DLL at: `"$result`"."
        return $result
    }

    # If no KSP DLL was found, report and return null
    Write-Warning "Found no SymCrypt DLL within: `"$script:PWD`"."
    return $null
}

# Downloads the SymCrypt DLL from GitHub.
function download_symcrypt
{
    $errmsg = "Please download `"$script:SYMCRYPT_FILE_NAME`" manually and place it in your shell's working directory (`"$script:PWD`")."
    $errmsg = "$errmsg Then, run this script again to install it."

    # Query the available release files, and select the one that matches our OS
    # and hardware.
    $assets = query_github_release_files -RepoOwner "$script:SYMCRYPT_REPO_OWNER" `
                                               -RepoName "$script:SYMCRYPT_REPO_NAME" `
                                               -ReleaseTag "$script:SYMCRYPT_REPO_RELEASE"
    $asset= $null
    foreach ($asset in $assets)
    {
        # Look for the proper ZIP file
        if (($asset.name -match "windows") -and
            ($asset.name -match "$script:HARDWARE") -and
            ($asset.name -match "\.zip"))
        {
            $asset = $asset
            break
        }
    }

    # If no matching asset name was found, throw an error
    if (-not $asset)
    {
        $msg = "Failed to find a SymCrypt release file that matches the OS and hardware specification."
        $msg = "$msg (Searched GitHub release version `"$script:SYMCRYPT_REPO_RELEASE`".)"
        Write-Error "$msg $errmsg"
        return $script:STATUS_FAIL
    }

    # Download the asset and store it next to this script
    $download_path = Join-Path -Path "$script:PWD" -ChildPath "$($asset.name)"
    Write-Host "Downloading GitHub asset `"$($asset.name)`" to: `"$download_path`"..."
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$download_path"

    # Make sure the file was downloaded
    if (-not (Test-Path -Path "$download_path" -PathType "Leaf"))
    {
        $msg = "Failed to download GitHub asset $asset."
        Write-Error "$msg $errmsg"
        return $script:STATUS_FAIL
    }
    Write-Host "Downloaded GitHub asset successfully."

    # Unzip the contents; the SymCrypt DLL is within
    $asset_name_no_extension = [System.IO.Path]::GetFileNameWithoutExtension($asset.name)
    $extract_path = Join-Path -Path "$script:PWD" -ChildPath "$asset_name_no_extension"
    Write-Host "Extracting zip file `"$download_path`" to: `"$extract_path`"..."
    Expand-Archive -Path "$download_path" -DestinationPath "$extract_path" -Force

    # Make sure the extraction completed
    if (-not (Test-Path -Path "$extract_path" -PathType "Container"))
    {
        $msg = "Failed to download GitHub asset: $asset."
        Write-Error "$msg $errmsg"
        return $script:STATUS_FAIL
    }
    Write-Host "Extracted zip file contents successfully."

    return $script:STATUS_SUCCESS
}

# Main function for installing the SymCrypt DLL.
function main_symcrypt
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$Path=$null
    )

    Write-Host "---------------------"
    Write-Host "SymCrypt Installation"
    Write-Host "---------------------"

    # Is there an existing SymCrypt DLL that is already installed?
    # If so, return early; no action is needed.
    $symcrypt_install_path = Join-Path -Path "$script:SYMCRYPT_INSTALL_DIR" `
                                             -ChildPath "$script:SYMCRYPT_FILE_NAME"
    if (Test-Path -Path "$symcrypt_install_path" -PathType "Leaf")
    {
        Write-Host "SymCrypt is already installed at: `"$symcrypt_install_path`". Skipping."
        return $script:STATUS_SUCCESS
    }

    # Was a path provided? If not, attempt to find (or download) the SymCrypt
    # DLL.
    $path = $Path
    if (-not $path)
    {
        # Look for the SymCrypt DLL locally. If multiple are found, choose the
        # first one.
        $path = find_symcrypt
        if (-not $path)
        {
            Write-Host "Downloading SymCrypt version `"$script:SYMCRYPT_REPO_RELEASE`" from GitHub..."
            if ((download_symcrypt) -ne $script:STATUS_SUCCESS)
            {
                return $script:STATUS_FAIL
            }

            # Now that the DLL is downloaded, search for it again
            $path = find_symcrypt
            if (-not $path)
            {
                $msg = "Failed to find SymCrypt DLL within: `"$script:PWD`"."
                $msg = "$msg Please download `"$script:SYMCRYPT_FILE_NAME`" manually and place it in your shell's working directory (`"$script:PWD`""
                $msg = "$msg Then, run this script again to install it."
                Write-Error "$msg"
                return $script:STATUS_FAIL
            }
        }
    }

    # Verify that the chosen path points to a valid SymCrypt DLL file
    $path_resolution = Resolve-Path "$path"
    $path = $path_resolution.Path
    if ((verify_symcrypt_file -Path "$path") -ne $script:STATUS_SUCCESS)
    {
        $msg = "The path (`"$path`") does not point to a valid SymCrypt DLL file."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # Copy the SymCrypt DLL into System32
    $symcrypt_install_path = Join-Path -Path "$script:SYMCRYPT_INSTALL_DIR" `
                                             -ChildPath "$script:SYMCRYPT_FILE_NAME"
    Write-Host "Copying SymCrypt DLL from `"$path`" to `"$symcrypt_install_path`"..."
    Copy-Item -Path "$path" -Destination "$symcrypt_install_path" -Force

    # Make sure the file was copied
    if (-not (Test-Path -Path "$symcrypt_install_path" -PathType "Leaf"))
    {
        Write-Error "Failed to copy SymCrypt DLL from `"$path`" to `"$symcrypt_install_path`"."
        return $script:STATUS_FAIL
    }
    Write-Host "Copied new SymCrypt DLL successfully."

    return $script:STATUS_SUCCESS
}

# Shows the 'help menu' for the script.
function show_help
{
    Write-Host "Install AziHSM Dependencies."
    Write-Host ""
    Write-Host "Available Options:"
    Write-Host "------------------"
    Write-Host "-Help"
    Write-Host "    Shows this help menu."
    Write-Host "-KSPPath `"C:\path\to\azihsmksp.dll`""
    Write-Host "    (OPTIONAL) Specifies a custom path to the AziHSM KSP DLL to install."
    Write-Host "    Default: Searches the working directory for `"$script:AZIHSM_KSP_FILE_NAME`"."
    Write-Host "-DriverPath `"C:\path\to\driver_folder`""
    Write-Host "    (OPTIONAL) Specifies a custom path to a directory containing AziHSM driver files to install."
    Write-Host "    Default: Searches the working directory for driver files."
    Write-Host "-SymCryptPath `"C:\path\to\symcrypt.dll`""
    Write-Host "    (OPTIONAL) Specifies a custom path to the SymCrypt DLL to install."
    Write-Host "    Default: Searches the working directory for `"$script:SYMCRYPT_FILE_NAME`"."
    Write-Host "-SkipDriver"
    Write-Host "    (OPTIONAL) Skips the installation of the AziHSM driver."
    Write-Host "-SkipKSP"
    Write-Host "    (OPTIONAL) Skips the installation of the AziHSM KSP DLL."
    Write-Host "-SkipSymCrypt"
    Write-Host "    (OPTIONAL) Skips the installation of the SymCrypt DLL."

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
        [string]$DriverPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$KSPPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$SymCryptPath=$null,
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

    # Install the AziHSM driver
    if (-not $SkipDriver)
    {
        $status = main_driver -Path $DriverPath
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $status
        }
        Write-Host "SUCCESS: AziHSM driver has been installed.`n"
    }

    # Install the SymCrypt DLL
    if (-not $SkipSymCrypt)
    {
        $status = main_symcrypt -Path $SymCryptPath
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $status
        }
        Write-Host "SUCCESS: SymCrypt has been installed.`n"
    }

    # Install the AziHSM KSP DLL
    if (-not $SkipKSP)
    {
        $status = (main_ksp -Path $KSPPath)
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $status
        }
        Write-Host "SUCCESS: AziHSM KSP has been installed.`n"
    }

    if ((-not $SkipDriver) -or `
        (-not $SkipKSP) -or `
        (-not $SkipSymCrypt))
    {
        Write-Host "Installation complete."
    }
    return $script:STATUS_SUCCESS
}

$status = main @args
exit $status

