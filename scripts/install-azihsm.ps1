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
$script:SUPPORTED_ARCHIVE_TYPES = @(".zip", ".nupkg")

$script:GETDEVICEINFO_FILE_NAME = "get_device_info"

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

$script:AZIHSM_REPO_OWNER = "microsoft"
$script:AZIHSM_REPO_NAME = "AziHSM-Guest"

$script:SYMCRYPT_FILE_NAME = "symcrypt.dll"
$script:SYMCRYPT_INSTALL_DIR = "$env:SYSTEMROOT\System32"
$script:SYMCRYPT_REPO_OWNER = "microsoft"
$script:SYMCRYPT_REPO_NAME = "SymCrypt"
$script:SYMCRYPT_REPO_RELEASE = "v103.8.0"

# A small class used to store version compatibility information for different
# AziHSM device firmware versions.
class AziHSMVersionCompatInfo
{
    [string]$FirmwareVersion    # <-- The firmware version corresponding to each instance of this object.
    [string]$DriverVersionMin   # <-- The minimum compatible driver version for this firmware version.
    [string]$DriverVersionMax   # <-- The maximum compatible driver version for this firmware version.
    [string]$KSPVersionMin      # <-- The minimum compatible KSP version for this firmware version.
    [string]$KSPVersionMax      # <-- The maximum compatible KSP version for this firmware version.

    # Constructs a new instance of this class.
    AziHSMVersionCompatInfo([string] $fw_ver,
                            [string] $drv_ver_min,
                            [string] $drv_ver_max,
                            [string] $ksp_ver_min,
                            [string] $ksp_ver_max)
    {
        $this.FirmwareVersion = $fw_ver
        $this.DriverVersionMin = $drv_ver_min
        $this.DriverVersionMax = $drv_ver_max
        $this.KSPVersionMin = $ksp_ver_min
        $this.KSPVersionMax = $ksp_ver_max
    }

    # Helper function that converts the provided string to a  `Version` object.
    [Version] StringToVersion([string] $ver)
    {
        $pieces = $ver.Trim().Split(".")

        # If we don't have 4 individual components
        # (`Major.Minor.Build.Revision`), pad the array with zeroes.
        while ($pieces.Length -lt 4)
        {
            $pieces += @("0")
        }

        # Create and return the `Version` object.
        return [Version]::new($pieces[0], $pieces[1], $pieces[2], $pieces[3])
    }

    # Compares the provided driver version and returns `$true` if it fits
    # within this object's minimum and maximum driver version range.
    [bool] CheckDriverVersion([string] $drv_ver)
    {
        # Convert each string to a `Version` object, for accurate comparison.
        $ver = $this.StringToVersion($drv_ver)
        $ver_min = $this.StringToVersion($this.DriverVersionMin)
        $ver_max = $this.StringToVersion($this.DriverVersionMax)

        # If the given version is within the range, or equal to the min/max, it
        # is considered compatible.
        if ($ver -ge $ver_min -and $ver -le $ver_max)
        {
            return $true
        }
        return $false
    }

    # Compares the provided driver version and returns `$true` if it fits
    # within this object's minimum and maximum KSP version range.
    [bool] CheckKSPVersion([string] $ksp_ver)
    {
        # Convert each string to a `Version` object, for accurate comparison.
        $ver = $this.StringToVersion($ksp_ver)
        $ver_min = $this.StringToVersion($this.KSPVersionMin)
        $ver_max = $this.StringToVersion($this.KSPVersionMax)

        # If the given version is within the range, or equal to the min/max, it
        # is considered compatible.
        if ($ver -ge $ver_min -and $ver -le $ver_max)
        {
            return $true
        }
        return $false
    }

    # Compares with the provided firmware version string.
    #
    # * Returns 0 if the versions are equal
    # * Returns a negative value if the provided version is greater than `$this`'s version.
    # * Returns a positive value if the provided version is greater than `$this`'s version.
    [int] CompareFirmwareVersion([string] $fw_ver)
    {
        # Slice the extra portion of the firmware string off the end (if
        # present), and convert the strings to `Version` objects for comparison
        $fw_ver1 = $this.FirmwareVersion -replace "-\d+$", ""
        $fw_ver2 = $fw_ver -replace "-\d+$", ""
        $fw_ver1 = $this.StringToVersion($fw_ver1)
        $fw_ver2 = $this.StringToVersion($fw_ver2)

        # Compare the versions and return
        $ver_diff = $fw_ver1.CompareTo($fw_ver2)
        return $ver_diff
    }
}

# A table containing version compatibility information for specific AziHSM
# device firmware versions. Certain versions of AziHSM components are not
# backwards compatible and thus require specific versions to function properly.
# ------------------------------------------------------------------------------ #
#   FW Version          Driver Min     Driver Max     KSP Min        KSP Max
# ------------------------------------------------------------------------------ #
$script:AZIHSM_VERSION_COMPAT_INFO_v3255_50319201 = [AzIhsmVersionCompatInfo]::new(
    "3.2.5.5-50319201", "2.0.234.0",   "2.0.234.999", "2.0.234.0",   "2.0.234.999" # UNSUPPORTED FW VERSION
);
$script:AZIHSM_VERSION_COMPAT_INFO_v3337_50613014 = [AzIhsmVersionCompatInfo]::new(
    "3.3.3.7-50613014", "2.0.413.0",   "2.0.413.999", "2.0.413.0",   "2.0.413.999" # UNSUPPORTED FW VERSION
);
$script:AZIHSM_VERSION_COMPAT_INFO_v3351_50702174 = [AzIhsmVersionCompatInfo]::new(
    "3.3.5.1-50702174", "2.0.486.0",   "2.0.486.999", "2.0.472.0",   "2.0.472.999"
);
$script:AZIHSM_VERSION_COMPAT_INFO_v3436_50926175 = [AzIhsmVersionCompatInfo]::new(
    "3.4.3.6-50926175", "2.0.591.0",   "2.0.591.999", "2.0.591.0",   "2.0.591.999"
);
$script:AZIHSM_VERSION_COMPAT_INFO_v3437_51001222 = [AzIhsmVersionCompatInfo]::new(
    "3.4.3.7-51001222", "2.0.591.0",   "2.0.591.999", "2.0.591.0",   "2.0.591.999"
);
$script:AZIHSM_VERSION_TABLE = @{
    # FW Version 3.2.5.5
    "3.2.5.5-50319201" = $script:AZIHSM_VERSION_COMPAT_INFO_v3255_50319201;
    # FW Version 3.3.3.7
    "3.3.3.7-50613014" = $script:AZIHSM_VERSION_COMPAT_INFO_v3337_50613014;
    # FW Version 3.3.5.1
    "3.3.5.1-50702174" = $script:AZIHSM_VERSION_COMPAT_INFO_v3351_50702174;
    # FW Version 3.4.3.6
    "3.4.3.6-50926175" = $script:AZIHSM_VERSION_COMPAT_INFO_v3436_50926175;
    # FW Version 3.4.3.7
    "3.4.3.7-51001222" = $script:AZIHSM_VERSION_COMPAT_INFO_v3437_51001222;
}

# Helper function that takes in a firmware version string (that may be
# incomplete) and sanitizies it to be a full firmware version string.
#
# This works by converting from a list of known values. If the provided
# firmware version is not recognized, the original string will be returned.
#
# This addresses an issue with older versions of the AziHSM driver that reports
# an incomplete firmware version string.
function sanitize_fw_version
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$FwVersion
    )

    # Create a table of known firmware version mappings.
    $table = @{
        "2.1-41219225" = "3.2.2.1-41219225";
        "5.5-50319201" = "3.2.5.5-50319201";
        "3.7-50613014" = "3.3.3.7-50613014";
        "5.1-50702174" = "3.3.5.1-50702174";
        "1.1-50805020" = "3.4.1.1-50805020";
        "1.2-50807234" = "3.4.1.2-50807234";
        "3.6-50926175" = "3.4.3.6-50926175";
        "3.7-51001222" = "3.4.3.7-51001222";
    }

    # If the provided string matches a table entry, return the full string.
    # Otherwise, just return the original.
    if ($table.ContainsKey($FwVersion.Trim()))
    {
        return $table["$FwVersion"]
    }
    return "$FwVersion"
}

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

# Helper function that pings a GitHub endpoint and returns a list of release
# tags for a specific repository.
function query_github_release_tags
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$RepoOwner,
        [Parameter(Mandatory=$true)]
        [string]$RepoName
    )

    # Build a GitHub URL with the provided parameters
    $url = "https://api.github.com/repos/$RepoOwner/$RepoName/releases"

    # Build headers and send a HTTP request to the URL
    $headers = @{
        "Accept" = "application/json"
    }
    $response = $null
    try
    {
        $response = Invoke-RestMethod -Uri "$url" `
                                      -Headers $headers `
                                      -ErrorAction "Stop"
    }
    catch
    {
        Write-Error "Failed to query GitHub releases for repository `"$RepoOwner/$RepoName`"."
        return $null
    }

    # Iterate through each release object and retrieve its tag name.
    $tags = @()
    foreach ($release in $response)
    {
        $tags += @($release.tag_name)
    }
    return $tags
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
    $response = $null
    try
    {
        $response = Invoke-RestMethod -Uri "$url" `
                                      -Headers $headers `
                                      -ErrorAction "Stop"
    }
    catch
    {
        Write-Error "Failed to query GitHub release `"$ReleaseTag`" in repository `"$RepoOwner/$RepoName`"."
        return $null
    }

    # Get the asset URL and query it; return the result (a list of objects
    # describing each asset)
    $asset_url = $response.assets_url
    try
    {
        $response = Invoke-RestMethod -Uri "$asset_url" `
                                      -Headers $headers `
                                      -ErrorAction "Stop"
    }
    catch
    {
        Write-Error "Failed to query GitHub assets for release `"$ReleaseTag`" in repository `"$RepoOwner/$RepoName`"."
        return $null
    }
    return $response
}

function download_github_release_file
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AssetObject,
        [Parameter(Mandatory=$true)]
        [string]$DownloadPath
    )

    # Download the asset and store at the specified location
    Write-Host "Downloading GitHub asset `"$($AssetObject.name)`" to: `"$DownloadPath`"..."
    Invoke-WebRequest -Uri $AssetObject.browser_download_url -OutFile "$DownloadPath"

    # Make sure the file was downloaded
    if (-not (Test-Path -Path "$DownloadPath" -PathType "Leaf"))
    {
        Write-Error "Failed to download GitHub asset `"$($AssetObject.name)`"."
        return $script:STATUS_FAIL
    }

    Write-Host "Successfully downloaded GitHub asset `"$($AssetObject.name)`" to `"$DownloadPath`"."
    return $script:STATUS_SUCCESS
}

# Function that expands the provided `.zip` or `.nuget` archive.
# Returns a status code indicating success or failure.
#
# If `-Force` is specified, any existing destination directory will be deleted
# prior to expansion.
function expand_archive
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    # Make sure the provided file path is a ZIP, NuGet package, or other
    # supported archive type.
    $is_supported_archive_type = $false
    $ext = [System.IO.Path]::GetExtension("$Path")
    foreach ($supported_ext in $script:SUPPORTED_ARCHIVE_TYPES)
    {
        if ($ext.ToLower() -eq $supported_ext.ToLower())
        {
            $is_supported_archive_type = $true
            break
        }
    }
    if (-not $is_supported_archive_type)
    {
        $msg = "Archive `"$Path`" has unsupported extension (`"$ext`")."
        $msg = "$msg Supported extensions are: $script:SUPPORTED_ARCHIVE_TYPES"
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    # If the destination path already exists, don't proceed any further
    if (Test-Path -Path "$DestinationPath" -PathType "Container")
    {
        if (-not $Force)
        {
            $msg = "The destination path (`"$DestinationPath`") already exists."
            $msg = "$msg Skipping expansion of archive `"$Path`"."
            Write-Warning "$msg"
            return $script:STATUS_SUCCESS
        }

        # If `-Force` was specified, we'll forcefully delete the destination
        # directory before proceeding.
        Write-Host "Destination path (`"$DestinationPath`") already exists. Deleting."
        Remove-Item -Path "$DestinationPath" -Recurse -Force
        Write-Host  "Deleted existing destination path (`"$DestinationPath`")."
    }

    # Is the archive a NuGet package (`.nupkg`)? If so, we need to temporarily
    # rename it to be `.zip`, so it can be processed by the `Expand-Archive`
    # function. (NuGet packages are zip archives.)
    $path_new = "$Path"
    $ext_old = $ext
    $ext_new = $null
    if ($ext_old.ToLower() -eq ".nupkg")
    {
        $ext_new = ".zip"
        $path_new = [System.IO.Path]::ChangeExtension("$path_new", "$ext_new")
        Move-Item -Path "$Path" -Destination "$path_new" -Force
        Write-Host "Temporarily renamed archive `"$Path`" to: `"$path_new`"."
    }

    # Otherwise, expand the archive
    Expand-Archive -Path "$path_new" -DestinationPath "$DestinationPath" | Out-Null

    # Make sure the expanded directory was created
    if (-not (Test-Path -Path "$DestinationPath" -PathType "Container"))
    {
        $msg = "Failed to expand archive `"$path_new`"."
        $msg = "$msg Destination directory `"$DestinationPath`" could not be found."
        Write-Error "$msg"
        return $script:STATUS_FAIL
    }

    Write-Host "Expanded archive `"$path_new`" to destination: `"$DestinationPath`"."

    # Change the archive's extension back to its original extension, if
    # applicable
    if ($ext_new -ne $null)
    {
        [System.IO.Path]::ChangeExtension("$path_new", "$ext_old") | Out-Null
        Move-Item -Path "$path_new" -Destination "$Path" -Force
        Write-Host "Restored archive's original name (from: `"$Path`" to: `"$path_new`")."
    }

    return $script:STATUS_SUCCESS
}

# Helper function that queries the GitHub repo for `get_device_info`
# executables. A list of available executables is returned. If the query fails,
# or no executables files are found, `$null` is returned.
function query_github_getdeviceinfo_files
{
    # Start by querying the GitHub repo for all available release tags
    $tags = query_github_release_tags -RepoOwner "$script:AZIHSM_REPO_OWNER" `
                                      -RepoName "$script:AZIHSM_REPO_NAME"
    if ($tags -eq $null)
    {
        return $null
    }

    # For each release tag, determine what files are available to download.
    # Collect all `get_device_info` files discovered into a list.
    $gdi_files = @()
    foreach ($tag in $tags)
    {
        $release_files = query_github_release_files -RepoOwner "$script:AZIHSM_REPO_OWNER" `
                                                    -RepoName "$script:AZIHSM_REPO_NAME" `
                                                    -ReleaseTag "$tag"
        foreach ($file in $release_files)
        {
            # If the file name contains "get_device_info", we'll include it in the list
            # of returned files.
            $file_name_lower = $file.name.ToLower()
            if ($file_name_lower -like "*get_device_info*")
            {
                $gdi_files += @($file)

                # While we're at it, we'll parse the version number out of this
                # exsecutable and store it as an extra field in this object.
                if ($file_name_lower -match "(?<!\w)\d+(?:\.\d+)+(?!\w)")
                {
                    $version_str = $matches[0]
                    $file | Add-Member -MemberType NoteProperty -Name "azihsm_get_device_info_version" -Value "$version_str"
                }
            }
        }
    }

    # If no files were found, return `$null`.
    if ($gdi_files.Length -eq 0)
    {
        Write-Warning "Found no `"$script:GETDEVICEINFO_FILE_NAME`" files across all GitHub releases."
        return $null
    }

    # Otherwise, sort the list of files based on the version numbers we parsed.
    # We'll sort descending, such that the latest version is first in the list.
    $gdi_files_sorted = @($gdi_files | Sort-Object -Property { [version]$_.azihsm_get_device_info_version } -Descending)

    # Print a list of the file names that were found.
    $gdi_files_len = $gdi_files_sorted.Length
    $msg = "Found $gdi_files_len `"$script:GETDEVICEINFO_FILE_NAME`" file(s) across all GitHub releases:"
    for ($i = 0; $i -lt $gdi_files_len; $i++)
    {
        $file = $gdi_files_sorted[$i]
        $msg = "$msg `"$($file.name)`" (version: $($file.azihsm_get_device_info_version))"
        if ($i -lt ($gdi_files_len - 1))
        {
            $msg = "$msg,"
        }
    }
    Write-Host "$msg"

    return $gdi_files_sorted
}

# Helper function that expands an archive that is expected to contain a
# `get_device_info` executable.
function expand_getdeviceinfo_archive
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath
    )

    # Next, create a directory path at which we'll expand the archive.
    $arch_obj = Get-Item "$SourcePath"
    $arch_noextension = $arch_obj.BaseName
    $arch_dir = $arch_obj.DirectoryName
    $arch_dest = Join-Path -Path "$arch_dir" -ChildPath "${arch_noextension}_EXPANDED"

    # Expand the archive.
    $expand_result = expand_archive -Path "$SourcePath" `
                                    -DestinationPath "$arch_dest" `
                                    -Force
    if ($expand_result -ne $script:STATUS_SUCCESS)
    {
        Write-Error "Failed to expand `"$script:GETDEVICEINFO_FILE_NAME`" archive: `"$SourcePath`"."
        return $null
    }
    Write-Host "Expanded `"$script:GETDEVICEINFO_FILE_NAME`" archive `"$SourcePath`" to destination: `"$arch_dest`"."

    # Next, locate the `get_device_info` executable within the expanded archive.
    $gdi_path = find_getdeviceinfo -SearchPath "$arch_dest"
    if (-not $gdi_path)
    {
        Write-Error "Failed to locate `"$script:GETDEVICEINFO_FILE_NAME`" executable within expanded archive at: `"$arch_dest`"."
        return $null
    }

    Write-Host "Found `"$script:GETDEVICEINFO_FILE_NAME`" executable within expanded archive (`"$arch_dest`") at: `"$gdi_path`"."
    return $gdi_path
}

# Downloads a `get_device_info` executable file from GitHub.
function download_github_getdeviceinfo
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AssetObject
    )

    $download_path = Join-Path -Path "$script:PWD" -ChildPath "$($AssetObject.name)"
    $status = download_github_release_file -AssetObject $AssetObject `
                                           -DownloadPath "$download_path"
    if ($status -ne $script:STATUS_SUCCESS)
    {
        return $null
    }

    return expand_getdeviceinfo_archive -SourcePath "$download_path"
}

# Examines the given file path and ensures it points to a valid
# `get_device_info` executable file. Returns a value indicating a successful
# (or failed) verification.
function verify_getdeviceinfo_file
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Make sure the basename of the path matches the expected SymCrypt DLL name
    $basename = [System.IO.Path]::GetFileName("$Path")
    if (-not ($basename -like "*$script:GETDEVICEINFO_FILE_NAME*.exe"))
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

# Helper function that looks for a `get_device_info` executable file in the
# working directory (or the provided directory). If multiple are found, the
# path to the first-found executable is returned. If no `get_device_info`
# executable is found, `$null` is returned.
function find_getdeviceinfo
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$SearchPath="$script:PWD"
    )

    # Search the working directory for the executable
    $paths = @(Get-ChildItem -Path "$SearchPath" -Filter "*$script:GETDEVICEINFO_FILE_NAME*.exe" -Recurse)
    $paths_len = $paths.Length
    if ($paths_len -ge 1)
    {
        $msg = "Found $paths_len `"$script:GETDEVICEINFO_FILE_NAME`" executable(s):"
        foreach ($path in $paths)
        {
            $msg = "$msg `"$($path.FullName)`""
        }
        Write-Host "$msg"

        # Grab the first result and return its path
        $result = $paths[0].FullName
        Write-Host "Selecting `"$script:GETDEVICEINFO_FILE_NAME`" executable at: `"$result`"."
        return $result
    }

    # If no executable was found, null
    return $null
}

# Finds and invokes the `get_device_info` utility, and parses the output to
# determine which versions of the AziHSM driver and AziHSM KSP are compatible
# with the connected device.
#
# The versions are returned. On failure, `$null` is returned.
function get_azihsm_device_info
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$GetDeviceInfoPath=$null
    )

    # Invoke the `get_device_info` utility and capture its output.
    Write-Host "Executing `"$GetDeviceInfoPath`" to retrieve connected AziHSM device information."
    $result = run_cmd -CmdName "$GetDeviceInfoPath"
    $out = $result.Output

    # If the utility didn't output anything, then it was unable to communicate
    # with the AziHSM device. This is likely because the device driver is not
    # installed.
    if ($out -eq $null -or $out.Length -eq 0)
    {
        $msg = "`"$GetDeviceInfoPath`" did not produce any output."
        $msg = "$msg Several reasons may explain this:`n`n"
        $msg = "${msg}1. The AziHSM driver was uninstalled before this could execute.`n"
        $msg = "${msg}2. This machine does not have an AziHSM device connected.`n"
        $msg = "${msg}3. This machine was not deployed with the proper VM tag, and thus was never given access to the AziHSM device.`n"
        $msg = "${msg}`n"
        $msg = "${msg}Please examine the script output for any errors, and follow the documentation to ensure you followed all steps correctly.`n"
        $msg = "${msg}If this VM is not one of the Azure VM sizes that are compatible with the AziHSM, please redeploy using a supported size.`n"
        $msg = "${msg}If this VM was not deployed with the proper VM tag, please deallocate this VM, apply the proper tag, then restart the VM. Or, you may deploy a new VM.`n"
        $msg = "${msg}If you have ruled all of the above possibilities out, please raise an issue on the GitHub repository."
        Write-Warning "$msg"
        return $null
    }

    # Create a custom object to contain the various pieces of information we're
    # about to parse from the output.
    $device_info = [PSCustomObject]@{
        DriverVersion = $null
        FirmwareVersion = $null
        HardwareVersion = $null
        PCIInfo = $null
    }

    # Read the output line-by-line:
    $lines = $out -split "`n"
    $fw_version = $null
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

        # Split the line into its key and value components
        $pieces = $line -split ":", 2
        $key = $pieces[0].Trim().ToLower()
        $value = $pieces[1].Trim().Trim('"')

        # Look for various keys and store their values:
        if ($key -like "*driver version*")
        {
            $device_info.DriverVersion = $value
            Write-Host "Discovered AziHSM device driver version: $value"
        }
        elseif ($key -like "*fw ver*")
        {
            $fw_version = sanitize_fw_version -FwVersion $value
            $device_info.FirmwareVersion = $fw_version
            Write-Host "Discovered AziHSM device firmware version: $fw_version"
        }
        elseif ($key -like "*hw ver*")
        {
            $device_info.HardwareVersion = $value
            Write-Host "Discovered AziHSM device hardware version: $value"
        }
        elseif ($key -like "*pci info*")
        {
            $device_info.PCIInfo = $value
            Write-Host "Discovered AziHSM device PCI info: $value"
        }
    }

    # Make sure all fields in custom object were filled.
    if (-not $device_info.DriverVersion -or
        -not $device_info.FirmwareVersion -or
        -not $device_info.HardwareVersion -or
        -not $device_info.PCIInfo)
    {
        $msg = "Failed to parse all device information from `"$GetDeviceInfoPath`" output."
        $msg = "$msg Received output:`n$out"
        Write-Error "$msg"
        return $null
    }

    return $device_info
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

# Helper function that queries the GitHub repo for driver binaries. A list of
# available driver releases is returned. If the query fails, or no driver files
# are found, `$null` is returned.
function query_github_drivers
{
    # Start by querying the GitHub repo for all available release tags
    $tags = query_github_release_tags -RepoOwner "$script:AZIHSM_REPO_OWNER" `
                                      -RepoName "$script:AZIHSM_REPO_NAME"
    if ($tags -eq $null)
    {
        return $null
    }

    # For each release tag, determine what files are available to download.
    # Collect all driver files discovered into a list.
    $driver_files = @()
    foreach ($tag in $tags)
    {
        $release_files = query_github_release_files -RepoOwner "$script:AZIHSM_REPO_OWNER" `
                                                    -RepoName "$script:AZIHSM_REPO_NAME" `
                                                    -ReleaseTag "$tag"
        foreach ($file in $release_files)
        {
            # If the file name contains "driver", we'll include it in the list
            # of returned files.
            $file_name_lower = $file.name.ToLower()
            if ($file_name_lower -like "*driver*")
            {
                $driver_files += @($file)

                # While we're at it, we'll parse the version number out of this
                # driver version and store it as an extra field in this object.
                # This will come in handy later when we're trying to determine
                # which driver version to install.
                if ($file_name_lower -match "(?<!\w)\d+(?:\.\d+)+(?!\w)")
                {
                    $version_str = $matches[0]
                    $file | Add-Member -MemberType NoteProperty -Name "azihsm_driver_version" -Value "$version_str"
                }
            }
        }
    }

    # If no driver files were found, return `$null`.
    if ($driver_files.Length -eq 0)
    {
        Write-Warning "Found no AziHSM driver files across all GitHub releases."
        return $null
    }

    # Otherwise, sort the list of drivers based on the version numbers we
    # parsed. We'll sort descending, such that the latest driver version is
    # first in the list.
    $driver_files_sorted = @($driver_files | Sort-Object -Property { [version]$_.azihsm_driver_version } -Descending)

    # Print a list of the file names that were found.
    $driver_files_len = $driver_files_sorted.Length
    $msg = "Found $driver_files_len AziHSM driver file(s) across all GitHub releases:"
    for ($i = 0; $i -lt $driver_files_len; $i++)
    {
        $file = $driver_files_sorted[$i]
        $msg = "$msg `"$($file.name)`" (version: $($file.azihsm_driver_version))"
        if ($i -lt ($driver_files_len - 1))
        {
            $msg = "$msg,"
        }
    }
    Write-Host "$msg"

    return $driver_files_sorted
}

function expand_driver_archive
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath
    )

    # Next, create a directory path at which we'll expand the archive.
    $arch_obj = Get-Item "$SourcePath"
    $arch_noextension = $arch_obj.BaseName
    $arch_dir = $arch_obj.DirectoryName
    $arch_dest = Join-Path -Path "$arch_dir" -ChildPath "${arch_noextension}_EXPANDED"

    # Expand the archive.
    $expand_result = expand_archive -Path "$SourcePath" `
                                    -DestinationPath "$arch_dest" `
                                    -Force
    if ($expand_result -ne $script:STATUS_SUCCESS)
    {
        Write-Error "Failed to expand driver archive: `"$SourcePath`"."
        return $null
    }

    Write-Host "Expanded driver archive `"$SourcePath`" to destination: `"$arch_dest`"."
    return $arch_dest
}

# Helper function that downloads an AziHSM driver file and expands the
# downloaded archive.
function download_github_driver
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AssetObject
    )

    # Start by downloading the driver asset from GitHub.
    $download_path = Join-Path -Path "$script:PWD" -ChildPath "$($AssetObject.name)"
    $status = download_github_release_file -AssetObject $AssetObject `
                                           -DownloadPath "$download_path"
    if ($status -ne $script:STATUS_SUCCESS)
    {
        return $null
    }

    return expand_driver_archive -SourcePath "$download_path"
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
function install_driver
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Verify the driver files
    $path = (Resolve-Path "$Path").Path
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
        Write-Host "An existing AziHSM driver is already installed as: `"$($driver_info.PublishedName)`"."

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
    Write-Host "Installed new AziHSM driver (`"$driver_inf_path`") successfully as: `"$($driver_info.PublishedName)`"."

    return $script:STATUS_SUCCESS
}

# Helper function that queries the GitHub repo for KSP binaries. A list of
# available KSP releases is returned. If the query fails, or no driver files
# are found, `$null` is returned.
function query_github_ksps
{
    # Start by querying the GitHub repo for all available release tags
    $tags = query_github_release_tags -RepoOwner "$script:AZIHSM_REPO_OWNER" `
                                      -RepoName "$script:AZIHSM_REPO_NAME"
    if ($tags -eq $null)
    {
        return $null
    }

    # For each release tag, determine what files are available to download.
    # Collect all KSP files discovered into a list.
    $ksp_files = @()
    foreach ($tag in $tags)
    {
        $release_files = query_github_release_files -RepoOwner "$script:AZIHSM_REPO_OWNER" `
                                                    -RepoName "$script:AZIHSM_REPO_NAME" `
                                                    -ReleaseTag "$tag"
        foreach ($file in $release_files)
        {
            # If the file name contains "KSP", we'll include it in the list
            # of returned files.
            $file_name_lower = $file.name.ToLower()
            if ($file_name_lower -like "*ksp*")
            {
                $ksp_files += @($file)

                # While we're at it, we'll parse the version number out of this
                # KSP version and store it as an extra field in this object.
                # This will come in handy later when we're trying to determine
                # which KSP version to install.
                if ($file_name_lower -match "(?<!\w)\d+(?:\.\d+)+(?!\w)")
                {
                    $version_str = $matches[0]
                    $file | Add-Member -MemberType NoteProperty -Name "azihsm_ksp_version" -Value "$version_str"
                }
            }
        }
    }

    # If no KSP files were found, return `$null`.
    if ($ksp_files.Length -eq 0)
    {
        Write-Warning "Found no AziHSM KSP files across all GitHub releases."
        return $null
    }

    # Otherwise, sort the list of KSPs based on the version numbers we parsed.
    # We'll sort descending, such that the latest KSP version is first in the
    # list.
    $ksp_files_sorted = @($ksp_files | Sort-Object -Property { [version]$_.azihsm_ksp_version } -Descending)

    # Print a list of the file names that were found.
    $ksp_files_len = $ksp_files_sorted.Length
    $msg = "Found $ksp_files_len AziHSM KSP file(s) across all GitHub releases:"
    for ($i = 0; $i -lt $ksp_files_len; $i++)
    {
        $file = $ksp_files_sorted[$i]
        $msg = "$msg `"$($file.name)`" (version: $($file.azihsm_ksp_version))"
        if ($i -lt ($ksp_files_len - 1))
        {
            $msg = "$msg,"
        }
    }
    Write-Host "$msg"

    return $ksp_files_sorted
}

# Examines the provided KSP DLL and determines the version.
# On success, the version string is returned.
# On fail, `$null` is returned.
function get_ksp_version
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $ksp_info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$Path")
    if ($ksp_info -and $ksp_info.FileVersion)
    {
        return $ksp_info.FileVersion.Replace("-", ".")
    }

    return $null
}

# Helper function that looks for a KSP binary in the provided directory.
# If multiple are found, the path to the first-found DLL is returned.
# If no KSP DLL is found, `$null` is returned.
function find_ksp
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$SearchPath="$script:PWD"
    )

    # Search the working directory for the KSP DLL
    $paths = @(Get-ChildItem -Path "$SearchPath" -Filter "$script:AZIHSM_KSP_FILE_NAME" -Recurse)
    $paths_len = $paths.Length
    if ($paths_len -ge 1)
    {
        $msg = "Found $paths_len AziHSM KSP DLL(s) within `"$SearchPath`":"
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
    Write-Warning "Found no AziHSM KSP DLL within: `"$SearchPath`"."
    return $null
}

# Expands the path to the provided KSP archive, and returns the path to the KSP
# DLL within. If the KSP DLL can't be found, `$null` is returned.
function expand_ksp_archive
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath
    )

    # Next, create a directory path at which we'll expand the archive.
    $arch_obj = Get-Item "$SourcePath"
    $arch_noextension = $arch_obj.BaseName
    $arch_dir = $arch_obj.DirectoryName
    $arch_dest = Join-Path -Path "$arch_dir" -ChildPath "${arch_noextension}_EXPANDED"

    # Expand the archive.
    $expand_result = expand_archive -Path "$SourcePath" `
                                    -DestinationPath "$arch_dest" `
                                    -Force
    if ($expand_result -ne $script:STATUS_SUCCESS)
    {
        Write-Error "Failed to expand KSP archive: `"$SourcePath`"."
        return $null
    }
    Write-Host "Expanded KSP archive `"$SourcePath`" to destination: `"$arch_dest`"."

    # Next, locate the KSP DLL within the expanded archive.
    $ksp_path = find_ksp -SearchPath "$arch_dest"
    if (-not $ksp_path)
    {
        Write-Error "Failed to locate KSP DLL within expanded archive at: `"$arch_dest`"."
        return $null
    }

    Write-Host "Found KSP DLL within expanded archive (`"$arch_dest`") at: `"$ksp_path`"."
    return $ksp_path
}

# Helper function that downloads an AziHSM KSP file from GitHub and expands the
# downloaded archive.
function download_github_ksp
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AssetObject
    )

    # Start by downloading the KSP asset from GitHub.
    $download_path = Join-Path -Path "$script:PWD" -ChildPath "$($AssetObject.name)"
    $status = download_github_release_file -AssetObject $AssetObject `
                                           -DownloadPath "$download_path"
    if ($status -ne $script:STATUS_SUCCESS)
    {
        return $null
    }

    # Expand the archive and return the path to the KSP DLL within.
    return expand_ksp_archive -SourcePath "$download_path"
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

# Installs the provided KSP DLL file.
function install_ksp
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $path = (Resolve-Path "$Path").Path
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
    $asset = $null
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
    $status = download_github_release_file -AssetObject $asset `
                                           -DownloadPath "$download_path"

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
    Write-Host "-GetDeviceInfoPath `"C:\path\to\$script:GETDEVICEINFO_FILE_NAME`" or `"C:\path\to\get_device_info_release_archive.[zip|nupkg]`""
    Write-Host "    (OPTIONAL) Specifies a custom path to the `"$script:GETDEVICEINFO_FILE_NAME`" executable."
    Write-Host "    Default: Downloads the `"$script:GETDEVICEINFO_FILE_NAME`" to the working directory."
    Write-Host "-KSPPath `"C:\path\to\$script:AZIHSM_KSP_FILE_NAME`" or `"C:\path\to\ksp_release_archive.[zip|nupkg]`""
    Write-Host "    (OPTIONAL) Specifies a custom path to the AziHSM KSP DLL to install."
    Write-Host "    Default: Downloads a compatible `"$script:AZIHSM_KSP_FILE_NAME`" from the GitHub repository."
    Write-Host "-DriverPath `"C:\path\to\driver_folder`" or `"C:\path\to\driver_release_archive.[zip|nupkg]`""
    Write-Host "    (OPTIONAL) Specifies a custom path to a directory containing AziHSM driver files to install."
    Write-Host "    Default: Downloads compatible driver files from the GitHub repository."
    Write-Host "-SymCryptPath `"C:\path\to\symcrypt.dll`""
    Write-Host "    (OPTIONAL) Specifies a custom path to the SymCrypt DLL to install."
    Write-Host "    Default: Downloads `"$script:SYMCRYPT_FILE_NAME`" to the working directory."

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
        [string]$GetDeviceInfoPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$DriverPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$KSPPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$SymCryptPath=$null
    )

    if ($Help)
    {
        return show_help
    }

    # This script automatically detects the firmware version of the AziHSM
    # device connected to this machine. Knowing the firmware version allows the
    # script to determine which versions of the AziHSM driver and AziHSM KSP to
    # install.
    #
    # In order to detect the firmware version, however, the AziHSM driver must
    # already be installed. This is a "chicken and egg" problem.
    #
    # To solve this problem, the script will do the following:
    #
    # 1. If `DriverPath` is provided, this driver will be installed without
    #    question. (It is assumed that the caller has already checked for
    #    compatibility.)
    # 2. If `DriverPath` is not provided:
    #     1. The script will download and install one of the driver versions
    #        from the GitHub repo. This is considered the "temporary driver".
    #     2. The script will download the `get_device_info.exe` utilty from the
    #        GitHub repo and execute it (making use of the temporary driver) to
    #        determine the firmware version of the connected AziHSM device.
    #     3. The script will use the firmware version to select (and download) a
    #        compatible driver version. If the chosen driver version doesn't match
    #        the temporary driver that is currently installed, the temporary
    #        driver will be uninstalled, and the compatible driver will be
    #        installed.
    #
    # Similarly, for the KSP:
    #
    # 1. If `KSPPath` is provided, then it will be installed without question.
    #    (Again, it is assumed that the caller has already checked for
    #    compatibility.)
    # 2. If `KSPPath` is not provided:
    #     1. The script will execute the `get_device_info.exe` utility to
    #        determine the firmware version.
    #     2. The script will use the firmware version to select (and download) a
    #        compatible KSP version. This KSP will then be instaslled.

    # ------------------------- Driver Installation -------------------------- #
    Write-Host "--------------------------"
    Write-Host "AziHSM Driver Installation"
    Write-Host "--------------------------"
    $temporary_driver_required = $false
    $temporary_driver_version = $null
    $driver_files_available = $null

    # If a driver path was provided, install it.
    if ($DriverPath)
    {
        Write-Host "A driver path was provided: `"$DriverPath`"."

        $err = "Please ensure the provided driver path points to either:"
        $err = "$err 1. A directory containing AziHSM driver files ($script:AZIHSM_DRIVER_FILES), or"
        $err = "$err 2. An archive file ($script:SUPPORTED_ARCHIVE_TYPES) containing the driver files."

        $driver_path = "$DriverPath"

        # Was a path to a file (not a directory) provided? If so, we'll assume
        # it is an archive file containing the driver files.
        if (Test-Path -Path "$DriverPath" -PathType "Leaf")
        {
            # Expand the archive to a temporary directory
            $driver_path = expand_driver_archive -SourcePath "$DriverPath"
            if ($driver_path -eq $null)
            {
                Write-Error "Failed to expand driver archive at provided path: `"$DriverPath`". $err"
                return $script:STATUS_FAIL
            }
        }

        # Attempt to install the drivers contained in the directory.
        $status = install_driver -Path "$driver_path"
        if ($status -ne $script:STATUS_SUCCESS)
        {
            Write-Error "Failed to install AziHSM driver from provided path: `"$DriverPath`". $err"
            return $script:STATUS_FAIL
        }
        Write-Host "SUCCESS: AziHSM driver has been installed.`n"
    }
    # Otherwise, we need to install a temporary driver, so we can use it to
    # detrmine the AziHSM device firmware version.
    else
    {
        $temporary_driver_required = $true
        $msg = "A driver path was not provided."
        $msg = "$msg This script will automatically download and install a compatible driver."
        Write-Host "$msg"

        # Query GitHub for a list of all available driver files.
        $driver_files_available = query_github_drivers

        # If no driver files were found, throw an error. The user will need to
        # download themselves and provide a path via `-DriverPath`.
        if ($driver_files_available -eq $null)
        {
            $msg = "This script could not find any AziHSM driver files to download from GitHub."
            $msg = "$msg Please manually download a driver package onto this machine, then use the `"-DriverPath`" argument to point this script at it."
            Write-Error "$msg"
            return $script:STATUS_FAIL
        }

        # Next, we need to decide which driver file to install as our
        # "temporary" driver.

        # If there is only one available, we'll download and install it, not
        # only as the temporary driver, but as the final driver. (Because there
        # are no other options.)
        $driver_files_available_len = $driver_files_available.Length
        $driver_asset = $null
        if ($driver_files_available_len -eq 1)
        {
            $driver_asset = $driver_files_available[0]
            $msg = "Only one AziHSM driver file is available to download from GitHub: `"$($driver_asset.name)`"."
            $msg = "$msg This will be installed."
            Write-Host "$msg"

            # Because only a single driver option was available, we can un-set
            # the `temporary_driver_required` flag. This is now our "final"
            # driver, not our "temporary" one.
            $temporary_driver_required = $false
        }
        # Otherwise, if there is more than one choice, we'll select the latest
        # driver to install.
        else
        {
            $driver_asset = $driver_files_available[0]
            $msg = "Multiple AziHSM driver files are available to download from GitHub."
            $msg = "$msg Selecting the latest driver version (`"$($driver_asset.name)`") to install as a temporary driver."
            Write-Host "$msg"
        }

        # Download the driver file and expand the archive.
        $driver_dir = download_github_driver -AssetObject $driver_asset
        if ($driver_dir -eq $null)
        {
            return $script:STATUS_FAIL
        }

        # Install the driver.
        $status = install_driver -Path "$driver_dir"
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $script:STATUS_FAIL
        }

        # If this was the only driver to install, meaning we are NOT treating
        # this as a temporary driver, print the success message now.
        if (-not $temporary_driver_required)
        {
            Write-Host "SUCCESS: AziHSM driver has been installed.`n"
        }
        # If we ARE treating this as a temporary driver, we need to save the
        # driver's version number for later, to determine if it is compatible
        # with the device firmware.
        else
        {
            $temporary_driver_version = $driver_asset.azihsm_driver_version
            Write-Host ""
        }
    }

    # ---------------------- Firmware Version Discovery ---------------------- #
    Write-Host "-----------------------------------"
    Write-Host "AziHSM Device Information Discovery"
    Write-Host "-----------------------------------"

    # If the `get_device_info` path was not specified, look for it.
    $gdi_path = "$GetDeviceInfoPath"
    if ($GetDeviceInfoPath)
    {
        Write-Host "A `"$script:GETDEVICEINFO_FILE_NAME`" path was provided: `"$GetDeviceInfoPath`"."

        $err = "Please ensure the provided `"$script:GETDEVICEINFO_FILE_NAME`" path points to either:"
        $err = "$err 1. A `"$script:GETDEVICEINFO_FILE_NAME`" executable, or"
        $err = "$err 2. An archive file ($script:SUPPORTED_ARCHIVE_TYPES) containing the executable, or"
        $err = "$err 3. A directory containing the executable."

        # Does the `get_device_info` path point to a valid executable? If it
        # doesn't, we'll to see if the user provided a path to something else
        # (a directory or an archive).
        if ((verify_getdeviceinfo_file -Path "$GetDeviceInfoPath") -ne $script:STATUS_SUCCESS)
        {
            # Does the path point to a directory instead? If so, we'll look for
            # the executable within the directory.
            if (Test-Path -Path "$GetDeviceInfoPath" -PathType "Container")
            {
                # If we can't find the executable within the directory, throw
                # an error.
                $gdi_path = find_getdeviceinfo -SearchPath "$GetDeviceInfoPath"
                if (-not $gdi_path)
                {
                    $msg = "The provided `"$script:GETDEVICEINFO_FILE_NAME`" directory (`"$GetDeviceInfoPath`")"
                    $msg = "$msg does not contain a valid `"$script:GETDEVICEINFO_FILE_NAME`" executable."
                    Write-Error "$msg $err"
                    return $script:STATUS_FAIL
                }
            }
            # Otherwise, we assume the path points to an archive file. Attempt
            # to expand the archive.
            else
            {
                $gdi_path = expand_getdeviceinfo_archive -SourcePath "$GetDeviceInfoPath"
                if (-not $gdi_path)
                {
                    $msg = "Failed to expand `"$script:GETDEVICEINFO_FILE_NAME`" archive (`"$GetDeviceInfoPath`")."
                    Write-Error "$msg $err"
                    return $script:STATUS_FAIL
                }
            }
        }
    }
    else
    {
        $msg = "A `"$script:GETDEVICEINFO_FILE_NAME`" path was not provided."
        $msg = "$msg This script will automatically download one."
        Write-Host "$msg"

        # Query the GitHub repository for all available `get_device_info` files.
        $gdi_files_available = query_github_getdeviceinfo_files
        if ($gdi_files_available.Length -eq 0)
        {
            $msg = "Found no `"$script:GETDEVICEINFO_FILE_NAME`" executables across all GitHub releases."
            $msg = "$msg Please download it manually and place it in your shell's working directory (`"$script:PWD`")."
            $msg = "$msg Then, run this script again."
            Write-Error "$msg"
            return $script:STATUS_FAIL
        }

        # Select the newest version of the executable.
        $gdi_asset = $gdi_files_available[0]
        $msg = "Downloading latest `"$script:GETDEVICEINFO_FILE_NAME`" executable from GitHub release: `"$($gdi_asset.name)`"."

        # Attempt to download the executable.
        $gdi_path = download_github_getdeviceinfo -AssetObject $gdi_asset
        if ($gdi_path -eq $null)
        {
            $msg = "Failed to download `"$script:GETDEVICEINFO_FILE_NAME`" executable from GitHub release `"$($gdi_asset.name)`"."
            $msg = "$msg Please download it manually and place it in your shell's working directory (`"$script:PWD`")."
            $msg = "$msg Then, run this script again."
            Write-Error "$msg"
            return $script:STATUS_FAIL
        }

        Write-Host "Downloaded `"$($gdi_asset.name)`" executable to: `"$gdi_path`"."
    }

    # Execute the `get_device_info` utility to retrieve device information.
    $info = get_azihsm_device_info -GetDeviceInfoPath "$gdi_path"
    if ($info -eq $null)
    {
        Write-Error "Failed to retrieve AziHSM device information."
        return $script:STATUS_FAIL
    }

    # Perform a lookup of the firmware version in the global version
    # compatibility table to determine what versions of the driver and KSP are
    # compatible.
    $compatible_versions = $null
    if ($script:AZIHSM_VERSION_TABLE.ContainsKey($info.FirmwareVersion))
    {
        $versions = $script:AZIHSM_VERSION_TABLE[$info.FirmwareVersion]

        # Log some of the version compatibility information.
        $msg = "AziHSM device firmware version `"$($info.FirmwareVersion)`" detected."
        Write-Host "$msg"
        $msg = "Compatible driver versions:"
        $msg = "$msg minimum of `"$($versions.DriverVersionMin)`", maximum of `"$($versions.DriverVersionMax)`"."
        Write-Host "$msg"
        $msg = "Compatible KSP versions:"
        $msg = "$msg minimum of `"$($versions.KSPVersionMin)`", maximum of `"$($versions.KSPVersionMax)`"."
        Write-Host "$msg"

        # Is the currently-installed driver version incompatible with the
        # firmware? If it is, log a warning to the user.
        if (-not $versions.CheckDriverVersion($info.DriverVersion))
        {
            $msg = "The installed AziHSM driver version (`"$($info.DriverVersion)`")"
            $msg = "$msg is NOT compatible with the device firmware version (`"$($info.FirmwareVersion)`")."
            $msg = "$msg Compatible driver versions are between `"$($versions.DriverVersionMin)`" and `"$($versions.DriverVersionMax)`"."
            Write-Warning "$msg"
        }
        # If the driver is compatible, log it.
        else
        {
            $msg = "The installed AziHSM driver version (`"$($info.DriverVersion)`")"
            $msg = "$msg is compatible with the device firmware version (`"$($info.FirmwareVersion)`")."
            Write-Host "$msg"
        }

        $compatible_versions = $versions
    }
    else
    {
        $msg = "AziHSM device firmware version `"$($info.FirmwareVersion)`" does not have defined compatibility information."
        Write-Host "$msg"

        # If the firmware version is not found in the compatibility table
        # (meaning it's a firmware version we haven't explicitly documented),
        # we need to decide how to proceed.
        #
        # Start by comparing with firmware v3.4.3.7
        $fw_v3437_cmp = $script:AZIHSM_VERSION_COMPAT_INFO_v3437_51001222.CompareFirmwareVersion($info.FirmwareVersion)

        # CASE 1:
        # If the firmware version is less than v3.4.3.7, then it is too early
        # of a firmware version for us to support it. Output an error.
        if ($fw_v3437_cmp -gt 0)
        {
            $msg = "This firmware version (`"$($info.FirmwareVersion)`") is too old to be supported by this installation script."
            $msg = "$msg Please submit an issue to the GitHub repository;"
            $msg = "$msg it is likely that this firmware version is not intended to be running on this AziHSM device."
            Write-Error "$msg"
            return $script:STATUS_FAIL
        }
        # CASE 2:
        # If the firmware version is greater than v3.4.3.7, we'll assume that
        # the latest driver and KSP versions are sufficient, but we'll warn the
        # user that there may be compatibility issues.
        else
        {
            $msg = "This firmware version (`"$($info.FirmwareVersion)`") is not explicitly documented in this script's compatibility table."
            $msg = "$msg However, it is likely that the latest driver and KSP versions are compatible."
            $msg = "$msg This script will install the latest versions, but please be aware that there may be compatibility issues."
            $msg = "$msg If you encounter any issues, please submit an issue to the GitHub repository."
            Write-Warning "$msg"
        }
    }

    Write-Host "SUCCESS: AziHSM device information has been retrieved.`n"

    # ----------------- Driver Reinstallation (If Necessary) ----------------- #
    # If we installed a temporary driver, and the compatible driver version is
    # not the same as the temporary driver, uninstall the temporary driver and
    # install the compatible driver now.
    if ($temporary_driver_required)
    {
        Write-Host "--------------------------------------"
        Write-Host "AziHSM Driver Installation (Continued)"
        Write-Host "--------------------------------------"

        # If the device firmware version didn't have defined compatibility
        # information, then we will assume the current driver version we have
        # installed (which is the latest version we could find on GitHub) is
        # sufficient.
        if ($compatible_versions -eq $null)
        {
            $msg = "No further action is needed; the device firmware version has no defined compatibility information,"
            $msg = "$msg and the latest driver version (`"$temporary_driver_version`") is already installed."
            Write-Host "$msg"
        }
        else
        {
            # Is the temporary driver we installed compatible with the FW version?
            # If so, there's nothing more we need to do for the driver; we can use
            # the temporary driver as the final driver.
            if ($compatible_versions.CheckDriverVersion($temporary_driver_version))
            {
                $msg = "The temporary driver version (`"$temporary_driver_version`") is compatible with the device firmware."
                $msg = "$msg No further driver installation is necessary."
                Write-Host "$msg"
            }
            # Otherwise, we need to download and install a driver that is
            # compatible with the device firmware.
            else
            {
                $msg = "The temporary driver version (`"$temporary_driver_version`") is NOT compatible with the device firmware."
                $msg = "$msg Proceeding to download and install a compatible driver version."
                Write-Host "$msg"

                # Iterate through the available driver files until we find one that
                # is compatible with the device firmware.
                $found_compatible_driver = $false
                foreach ($driver_asset in $driver_files_available)
                {
                    if ($compatible_versions.CheckDriverVersion($driver_asset.azihsm_driver_version))
                    {
                        $msg = "Found compatible driver (version `"$($driver_asset.azihsm_driver_version)`"): `"$($driver_asset.name)`"."
                        Write-Host "$msg"

                        # Download the driver file and expand the archive.
                        $driver_dir = download_github_driver -AssetObject $driver_asset
                        if ($driver_dir -eq $null)
                        {
                            return $script:STATUS_FAIL
                        }

                        # Install the driver.
                        $status = install_driver -Path "$driver_dir"
                        if ($status -ne $script:STATUS_SUCCESS)
                        {
                            return $script:STATUS_FAIL
                        }

                        # A compatible driver has been installed; break out of the
                        # loop and stop searching.
                        $found_compatible_driver = $true
                        break
                    }
                    else
                    {
                        $msg = "Driver version `"$($driver_asset.azihsm_driver_version)`""
                        $msg = "$msg is NOT compatible with device firmware version `"$($compatible_versions.FirmwareVersion)`"."
                        $msg = "$msg Skipping."
                        Write-Host "$msg"
                    }
                }

                # If we finished searching through all available driver files
                # without finding a compatible one, throw an error.
                if (-not $found_compatible_driver)
                {
                    $msg = "Failed to find a compatible AziHSM driver version for device firmware version `"$($info.FirmwareVersion)`"."
                    $msg = "$msg Please manually download a compatible driver package onto this machine, then use the `"-DriverPath`" argument to point this script at it.`n"
                    $msg = "${msg}If you do not see any compatible driver versions listed on the GitHub release page, please submit an issue to the GitHub repository;"
                    $msg = "$msg it is possible the device firmware is out of date, or a compatible driver package has not yet been published."
                    Write-Error "$msg"
                    return $script:STATUS_FAIL
                }
            }
        }

        Write-Host "SUCCESS: AziHSM driver has been installed.`n"
    }

    # ------------------------ SymCrypt Installation ------------------------- #
    Write-Host "---------------------"
    Write-Host "SymCrypt Installation"
    Write-Host "---------------------"

    $status = main_symcrypt -Path $SymCryptPath
    if ($status -ne $script:STATUS_SUCCESS)
    {
        return $status
    }
    Write-Host "SUCCESS: SymCrypt has been installed.`n"

    # --------------------------- KSP Installation --------------------------- #
    Write-Host "-----------------------"
    Write-Host "AziHSM KSP Installation"
    Write-Host "-----------------------"

    # If a KSP path was provided, install it without question. (We assume the
    # caller verified its compatibility.)
    if ($KSPPath)
    {
        Write-Host "A KSP path was provided: `"$KSPPath`"."
        $ksp_path = "$KSPPath"

        $err = "Please ensure the provided KSP path points to either:"
        $err = "$err 1. An AziHSM KSP DLL file (`"$script:AZIHSM_KSP_FILE_NAME`"), or"
        $err = "$err 2. An archive file ($script:SUPPORTED_ARCHIVE_TYPES) containing the KSP DLL, or"
        $err = "$err 3. A directory containing the KSP DLL."

        # Does the provided path point to a directory? If so, we'll look for a
        # DLL.
        if (Test-Path -Path "$KSPPath" -PathType "Container")
        {
            $msg = "The provided KSP path (`"$KSPPath`") is a directory."
            $msg = "$msg Searching for an AziHSM KSP DLL or archive within..."
            Write-Host "$msg"

            # Look for the KSP DLL within the provided directory
            $ksp_path = find_ksp -SearchPath "$KSPPath"
            if (-not $ksp_path)
            {
                $msg = "Failed to locate an AziHSM KSP DLL within: `"$KSPPath`"."
                Write-Error "$msg $err"
                return $script:STATUS_FAIL
            }
        }

        # If the provided file path fails verification (meaning it doesn't
        # point directly to a DLL file), we assume it is pointing to an
        # archive.
        if ((verify_ksp_file -Path "$ksp_path") -ne $script:STATUS_SUCCESS)
        {
            # Attempt to expand the provided KSP archive path.
            $ksp_path = expand_ksp_archive -SourcePath "$ksp_path"
            if ($ksp_path -eq $null)
            {
                Write-Error "Failed to expand KSP archive at: `"$KSPPath`". $err"
                return $script:STATUS_FAIL
            }
        }

        # Install the KSP DLL
        $status = install_ksp -Path "$ksp_path"
        if ($status -ne $script:STATUS_SUCCESS)
        {
            Write-Error "Failed to install KSP from path: `"$ksp_path`". $err"
            return $script:STATUS_FAIL
        }

        # Check the KSP's version against the device's firmware for
        # compatibility.
        if ($compatible_versions -ne $null)
        {
            # Attempt to retireve the version of the KSP binary we just
            # installed.
            $ksp_version = get_ksp_version -Path "$ksp_path"
            if ($ksp_version -eq $null)
            {
                $msg = "Failed to determine the version of the installed AziHSM KSP (`"$ksp_path`")."
                $msg = "$msg Cannot verify compatibility with device firmware version (`"$($info.FirmwareVersion)`")."
                Write-Warning "$msg"
            }
            # Compare against the compatible version information for this
            # firmware version.
            elseif (-not $compatible_versions.CheckKSPVersion($ksp_version))
            {
                $msg = "The installed AziHSM KSP version (`"$($ksp_version)`")"
                $msg = "$msg is NOT compatible with the device firmware version (`"$($compatible_versions.FirmwareVersion)`")."
                $msg = "$msg Compatible KSP versions are between `"$($compatible_versions.KSPVersionMin)`" and `"$($compatible_versions.KSPVersionMax)`"."
                Write-Warning "$msg"
            }
            # If the KSP is compatible, log it.
            else
            {
                $msg = "The installed AziHSM KSP version (`"$($ksp_version)`")"
                $msg = "$msg is compatible with the device firmware version (`"$($compatible_versions.FirmwareVersion)`")."
                Write-Host "$msg"
            }
        }
    }
    else
    {
        $msg = "A KSP path was not provided."
        $msg = "$msg This script will automatically download and install a compatible KSP."
        Write-Host "$msg"

        # Query GitHub for a list of all released KSP files. Throw an error if
        # no KSP files were found.
        $ksp_files_available = query_github_ksps
        if ($ksp_files_available -eq $null)
        {
            $msg = "This script could not find any AziHSM KSP files to download from GitHub."
            $msg = "$msg Please manually download a KSP package onto this machine, then use the `"-KSPPath`" argument to point this script at it."
            Write-Error "$msg"
            return $script:STATUS_FAIL
        }

        # Does this firmware version have defined compatibility information? If
        # it doesn't, we will assume the latest KSP version is sufficient.
        $ksp_asset = $null
        if ($compatible_versions -eq $null)
        {
            $ksp_asset = $ksp_files_available[0]
            $msg = "AziHSM device firmware version `"$($info.FirmwareVersion)`" does not have defined compatibility information."
            $msg = "$msg The latest KSP version (`"$($ksp_asset.azihsm_ksp_version)`") will be installed."
        }
        # Otherwise, if this firmware version DOES have defined compatibility
        # information, we need to find a compatible KSP version.
        else
        {
            # Iterate through each of the available KSP release files until we
            # find a version that is compatible.
            foreach ($asset in $ksp_files_available)
            {
                # If this KSP version is compatible with the device firmware,
                # select it and break out of the loop.
                if ($compatible_versions.CheckKSPVersion($asset.azihsm_ksp_version))
                {
                    $ksp_asset = $asset
                    $msg = "Found compatible KSP (version `"$($ksp_asset.azihsm_ksp_version)`"): `"$($ksp_asset.name)`"."
                    break
                }
                else
                {
                    $msg = "KSP version `"$($driver_asset.azihsm_driver_version)`""
                    $msg = "$msg is NOT compatible with device firmware version `"$($compatible_versions.FirmwareVersion)`"."
                    $msg = "$msg Skipping."
                    Write-Host "$msg"
                }
            }

            # If no compatible KSP version was found, throw an error.
            if ($ksp_asset -eq $null)
            {
                $msg = "Failed to find a KSP version that is compatible with the device firmware version (`"$($info.FirmwareVersion)`")."
                $msg = "$msg Please manually download a KSP package onto this machine, then use the `"-KSPPath`" argument to point this script at it."
                Write-Error "$msg"
                return $script:STATUS_FAIL
            }
        }

        # Download the KSP asset from GitHub.
        $ksp_path = download_github_ksp -AssetObject $ksp_asset
        if ($ksp_path -eq $null)
        {
            return $script:STATUS_FAIL
        }

        # Install the KSP.
        $status = install_ksp -Path "$ksp_path"
        if ($status -ne $script:STATUS_SUCCESS)
        {
            return $script:STATUS_FAIL
        }
    }
    Write-Host "SUCCESS: AziHSM KSP has been installed.`n"

    Write-Host "Installation complete."
    return $script:STATUS_SUCCESS
}

$status = main @args
exit $status

