# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script acts as a wrapper around the `logman` command-line utility to
# provide an interface for dumping AzIHSM ETW log messages to a file.

# Mapping of friendly tracing level names to their numeric ETW level values.
# These values mirror the authoritative mapping used by the AzIHSM KSP ETW
# provider in `plugins/ksp/src/etw_tracing.rs` (the `win_etw_provider::Level`
# values): ERROR=2, WARN=3, INFO=4, DEBUG (VERBOSE)=5, TRACE=6.
#
# The numeric value is passed to logman as the ETW *level* cutoff. logman
# captures every event whose level is less than or equal to the cutoff, so a
# higher value captures that level and everything more severe (for example, a
# cutoff of INFO/4 captures INFO, WARN, and ERROR events).
$LEVEL_NAME_MAP = @{
    "ERROR" = 2
    "WARN"  = 3
    "INFO"  = 4
    "DEBUG" = 5
    "TRACE" = 6
}

# Default ETW level cutoff used when the caller does not supply `-Level`. The
# value 0xFF preserves the historical behavior of capturing every event, since
# all real tracing levels fall well below 255.
$DEFAULT_ETW_LEVEL = 0xFF

# Maximum valid ETW level value. ETW encodes the level as a single byte, so
# valid numeric levels fall within the inclusive range 0 - 255.
$MAX_ETW_LEVEL = 0xFF

# Helper function to resolve a caller-supplied level into a numeric ETW level
# cutoff. The input may be a friendly name (case-insensitive: ERROR, WARN,
# INFO, DEBUG, TRACE) or a raw numeric value in decimal (e.g. "4") or
# hexadecimal (e.g. "0xFF") form. Returns the resolved integer, or $null when
# the input cannot be interpreted as a valid ETW level.
function resolve_etw_level
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Level
    )

    # friendly names take precedence and are matched case-insensitively
    $name = $Level.Trim().ToUpper()
    if ($LEVEL_NAME_MAP.ContainsKey($name))
    {
        return $LEVEL_NAME_MAP[$name]
    }

    # otherwise, interpret the value as a numeric literal (decimal or hex)
    $numeric = 0
    if ([int]::TryParse($Level, [ref]$numeric))
    {
        # decimal value parsed successfully
    }
    elseif ($Level -match '^0[xX][0-9a-fA-F]+$')
    {
        $numeric = [Convert]::ToInt32($Level, 16)
    }
    else
    {
        return $null
    }

    if ($numeric -lt 0 -or $numeric -gt $MAX_ETW_LEVEL)
    {
        return $null
    }

    return $numeric
}

# Helper function to launch logman.
function launch_logman
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$LogmanArgs
    )

    Write-Host "Launching logman with arguments: $LogmanArgs"
    $proc = Start-Process -FilePath "logman" `
                          -Wait `
                          -PassThru `
                          -NoNewWindow `
                          -ArgumentList "$LogmanArgs"
    return $proc.ExitCode
}

function show_help_menu
{
    Write-Host "Enable the dumping of ETW log messages to an ETL file."
    Write-Host ""
    Write-Host "Available Options:"
    Write-Host "------------------"
    Write-Host "-SessionName NAME"
    Write-Host "    The name of the trace session you wish to create."
    Write-Host "    You must choose a name that is unique."
    Write-Host "-OutputPath PATH"
    Write-Host "    The location at which the ETL file will be produced."
    Write-Host "    The ETL file will contain all dumped ETW log messages."
    Write-Host "-ProviderGUIDs GUID1,GUID2,..."
    Write-Host "    A list of one or more ETW provider GUID strings."
    Write-Host "    Each provider GUID will be added to the new trace session."
    Write-Host "-Level LEVEL (optional)"
    Write-Host "    The ETW level cutoff to capture. logman captures all events"
    Write-Host "    whose level is at or below (more severe than) this cutoff."
    Write-Host "    Accepts a friendly name (case-insensitive):"
    Write-Host "        ERROR (2), WARN (3), INFO (4), DEBUG (5), TRACE (6)"
    Write-Host "    or a raw numeric value in decimal (e.g. 4) or hex (e.g. 0xFF)."
    Write-Host "    For example, -Level INFO captures INFO, WARN, and ERROR events."
    Write-Host "    When omitted, every event is captured (default: 0xFF / TRACE)."
}

function main
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$true)]
        [string[]]$ProviderGUIDs,
        [Parameter(Mandatory=$true)]
        [string]$SessionName,
        [Parameter(Mandatory=$false)]
        [string]$Level
    )

    # resolve the ETW level cutoff. When -Level is omitted, fall back to the
    # default so that every event is captured (preserving the original
    # behavior). Any invalid input is rejected with a non-zero exit code.
    if ([string]::IsNullOrEmpty($Level))
    {
        $etw_level = $DEFAULT_ETW_LEVEL
    }
    else
    {
        $etw_level = resolve_etw_level -Level $Level
        if ($null -eq $etw_level)
        {
            Write-Error ("Invalid -Level value `"$Level`". Expected one of: " +
                "$($LEVEL_NAME_MAP.Keys -join ', ') (case-insensitive), or a " +
                "numeric value in the range 0-$MAX_ETW_LEVEL (decimal or hex, " +
                "e.g. 0xFF).")
            return 1
        }
    }

    # create a trace session
    $logman_args = "create trace `"$SessionName`" -ets -o `"$OutputPath`""
    $ret = launch_logman -LogmanArgs "$logman_args"
    if ($ret -ne 0)
    {
        Write-Error "Failed to create trace session with logman. Exit code: $ret."
        return $ret
    }

    # for each of the GUIDs provided, update the trace to track it
    foreach ($guid in $ProviderGUIDs)
    {
        $logman_args = "update `"$SessionName`" -ets -p `"{$guid}`" 0xFFFFFFFF $etw_level"
        $ret = launch_logman -LogmanArgs "$logman_args"
        if ($ret -ne 0)
        {
            Write-Error "Failed to add provider GUID `"$guid`" to trace session with logman. Exit code: $ret."
            return $ret
        }
    }

    # finally, launch another logman command to dump out the information on the
    # tracing session that was just created
    Write-Host "Newly created session:"
    $logman_args = "query `"$SessionName`" -ets"
    $ret = launch_logman -LogmanArgs "$logman_args"
    if ($ret -ne 0)
    {
        Write-Error "Failed to query for new session with logman. Exit code: $ret."
        return $ret
    }

    return 0
}

if ($args.Count -eq 0)
{
    show_help_menu
    exit 0
}

$retcode = main @args
exit $retcode

