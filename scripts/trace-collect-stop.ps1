# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script acts as a wrapper around the `logman` command-line utility to
# provide an interface for stopping a logman trace session.

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
    Write-Host "Disable the dumping of ETW Log messages to an ETL file."
    Write-Host ""
    Write-Host "Available Options:"
    Write-Host "------------------"
    Write-Host "-SessionName NAME"
    Write-Host "    The name of the trace session you wish to end."
}

function main
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$SessionName
    )
    
    # stop the trace session
    $logman_args = "stop `"$SessionName`" -ets"
    $ret = launch_logman -LogmanArgs "$logman_args"
    if ($ret -ne 0)
    {
        Write-Error "Failed to stop trace session with logman. Exit code: $proc_exit_code."
        return $ret
    }

    Write-Host "Trace session stopped successfully."
    return 0
}

if ($args.Count -eq 0)
{
    show_help_menu
    exit 0
}

$retcode = main @args
exit $retcode

