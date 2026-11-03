# Collecting KMPP Logs on Linux

KMPP and the AziHSM API library emit logs from the client application process through `syslog`.
In some debugging situations, it is valuable to collect these logs for examination.

On systems that use `systemd`, these messages are normally stored by `systemd-journald`.
This guide describes how to find these logs.

Access to the system journal may require membership in a journal-reading group or elevated permissions.
If a command reports insufficient permissions, try running it with `sudo`.

## Collect Application Logs

Replace `<application-unit>`, `<start-time>`, and `<end-time>` with values for your application and a short period that includes the issue:

```bash
sudo journalctl --unit "<application-unit>" --since "<start-time>" --until "<end-time>" --no-pager
```

For example, timestamps can use the form `2026-09-21 13:00:00`.
Keeping the time window narrow makes related messages easier to correlate.

If the application is not a `systemd` unit, search the journal for relevant messages during the reproduction window:

```bash
sudo journalctl --since "<start-time>" --until "<end-time>" --no-pager | grep -Ei "kmpp|azihsm|solutionType"
```

Also capture the application's standard output and standard error when starting it directly:

```bash
application_path="/path/to/application"
application_args=("--example-option" "example-value")
evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/azihsm-evidence.XXXXXX")"
output_file="${evidence_dir}/application-output.log"

"${application_path}" "${application_args[@]}" >"${output_file}" 2>&1
printf 'Application output written to %s\n' "${output_file}"
```

Replace `application_path` and `application_args` with the values for your application.
The command creates a unique evidence directory and writes the combined output to `application-output.log` within it, without overwriting an existing evidence file.

The AziHSM kernel driver is a separate logging layer.
Collect its messages independently when device or driver behavior may be relevant:

```bash
sudo journalctl --kernel --boot --since "<start-time>" --until "<end-time>" --no-pager
```

## Interpret `solutionType`

Find the final `solutionType` value for the operation:

* `5` means the operation used AziHSM.
* `1` means the operation used process isolation fallback.
* `3` means the operation used the TPM.

When multiple `solutionType` lines exist, use the last occurrence for that operation.
Any final value other than `5` means the operation did not use AziHSM.

Compare the timestamps of higher-level KMPP messages with nearby messages from `libazihsm_api_resilient.so`.
A resilient-library error can provide the lower-level context for the KMPP result.

## Evidence Checklist

Are you experiencing an issue with KMPP and/or AziHSM and want to investigate?
Start by collecting the following information:

* The application unit name or exact command line.
* A short journal window covering the failure, including timestamps.
* The application's standard output and standard error.
* All `solutionType` lines for the operation, with the final value identified.
* Nearby KMPP and `libazihsm_api_resilient.so` messages.
* Kernel journal messages from the same time window, when device access may be involved.
* The application user and its access to the AziHSM device.
* Whether the key handle was created and used by the same running process.

## Common Symptoms

| Symptom | What to check |
| --- | --- |
| KMPP cannot initialize | It is possible the AziHSM API library was not properly installed. Please see the [install instructions](./InstallLinux.md) to ensure all components were properly installed. |
| No KMPP messages appear | Confirm the time window, application unit or command, and journal permissions; also inspect captured standard output and standard error of your application. |
| The final `solutionType` is not `5` | The operation did not use AziHSM; instead, it used some other provider to perform cryptographic operations. Correlate the KMPP output lines with nearby AziHSM API messages. |
| Device access reports permission denied | Check the application user's groups and permissions on `/dev/azihsm*`. If needed, use the [install script](./InstallLinux.md) to ensure the application user has the proper group memberships. |
| A key handle works in one process but not another | Key handles are process-local, so confirm that the same running process created and used the handle. |
