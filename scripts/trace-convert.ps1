# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script acts as a wrapper around the `tracerpt` command-line utility to
# provide an interface for converting an `.etl` file to other formats.

function show_help_menu
{
    Write-Host "Dump an ETL file's contents to a TXT, CSV, or XML file."
    Write-Host ""
    Write-Host "Available Options:"
    Write-Host "------------------"
    Write-Host "-ETLFilePath PATH"
    Write-Host "    The path to the ETL file you wish to convert."
    Write-Host "-OutputPath PATH"
    Write-Host "    (OPTIONAL) The path to the TXT/CSV/XML file you wish to produce."
    Write-Host "    (Default: the same location as the file specified by ``-ETLFilePath``)"
    Write-Host "-OutputFormat [TXT|CSV|XML|EVTX]"
    Write-Host "    (OPTIONAL) The output file format you wish to produce."
    Write-Host "    (Default: CSV)"
}

# Helper function to launch a command-line utility.
function launch
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Cmd,
        [Parameter(Mandatory=$true)]
        [string]$CmdArgs
    )

    Write-Host "Launching $Cmd with arguments: $CmdArgs"
    $proc = Start-Process -FilePath "$Cmd" `
                          -Wait `
                          -PassThru `
                          -NoNewWindow `
                          -ArgumentList "$CmdArgs"
    return $proc.ExitCode
}

function main
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$ETLFilePath,
        [Parameter(Mandatory=$false)]
        [string]$OutputPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$OutputFormat="CSV"
    )

    # if no output path was given, create one, such that the generated file has
    # the same name and path as the original, but with an updated extension
    if (($OutputPath -eq $null) -or ($OutputPath.Length -eq 0))
    {
        $extension = $OutputFormat.ToLower()
        $OutputPath = "${ETLFilePath}.$extension"
    }

    # was `TXT` specified for the output format? If so, we'll want to invoke
    # `netsh` to convert the ETL file to TXT
    $output_format_lowercase = $OutputFormat.ToLower()
    if ($output_format_lowercase -eq "txt")
    {
        $netsh_args = "trace convert"
        $netsh_args = "$netsh_args input=`"$ETLFilePath`""
        $netsh_args = "$netsh_args output=`"$OutputPath`""
        $netsh_args = "$netsh_args overwrite=yes"

        # launch netsh
        $result = launch -Cmd "netsh" -CmdArgs "$netsh_args"
        if ($result -ne 0)
        {
            Write-Error "Failed to convert ETL file with netsh. Exit code: $result"
            return 1
        }
    }
    # otherwise, for CSV and XML output, we're instead launch `tracerpt`
    elseif (($output_format_lowercase -eq "csv") -or `
             ($output_format_lowercase -eq "xml") -or `
             ($output_format_lowercase -eq "evtx"))
    {
        $output_format_uppercase = $OutputFormat.ToUpper()
        $trpt_args = "`"$ETLFilePath`""
        $trpt_args = "$trpt_args -o `"$OutputPath`""
        $trpt_args = "$trpt_args -of $output_format_uppercase"
        
        # launch netsh
        $result = launch -Cmd "tracerpt" -CmdArgs "$trpt_args"
        if ($result -ne 0)
        {
            Write-Error "Failed to convert ETL file with tracerpt. Exit code: $result"
            return 1
        }
    }
    # in all other cases, complain that the output format is unrecognized
    else
    {
        $msg = "Unrecognized output format: `"$OutputFormat`"."
        $msg = "$msg Please specify one of the following: TXT, CSV, XML, EVTX"
        Write-Error "$msg"
        return 1
    }

    Write-Host "Success. View the converted file here: $OutputPath"
    return 0
}

if ($args.Count -eq 0)
{
    show_help_menu
    exit 0
}

$retcode = main @args
exit $retcode

