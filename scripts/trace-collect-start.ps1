# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script acts as a wrapper around the `logman` command-line utility to
# provide an interface for dumping AzIHSM ETW log messages to a file.

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
        [string]$SessionName
    )

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
        $logman_args = "update `"$SessionName`" -ets -p `"{$guid}`" 0xFFFFFFFF 0xFF"
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

