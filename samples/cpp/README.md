# Samples
The samples in this directory demonstrate how to utilize AziHSM in your application. They are written in C++.

## Prerequisites

Before running any samples under this folder, you should perform the following to set up the VM:

1. [Set up AziHSM related driver and library](../../README.md#getting-started)
2. [Install Visual Studio](https://visualstudio.microsoft.com/vs/community/)
3. [Install vcpkg for Visual Studio](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell)

**SECURE-KEY-RELEASE**

For this sample, additional setup is required. [See its README](./SECURE-KEY-RELEASE/README.md#prerequisites).

## Build the sample

1. Obtain this sample's source code by `git clone` or download source.
3. Open `cpp-samples.sln` in Visual Studio.  
4. Build using either Debug or Release build.

## Debug / Logging

### LNK1000 Build failure

When building a Release build, you might get following error

```
Error	LNK1000	Internal error during IMAGE::BuildImage
```

"Rebuild Solution" should fix this issue.

### Understand status code returned by NCrypt API 

AziHSM exposes its functions via NCrypt API, and reports error by returning an existing `SECURITY_STATUS` (`HRESULT`) error code.

You could lookup the error code and have a general idea about what went wrong.

### Get AziHSM KSP logs

You could get more detailed logging from AziHSM, which would include more details about why an error is thrown.

See [EventTracing.md](../../docs/EventTracing.md)

### Get Sample app logs

The sample apps use a combination of print to stdout/stderr, as well as [WIL](https://github.com/microsoft/wil)  for error logging.

By default, [WIL only logs to debugger window](https://github.com/microsoft/wil/wiki/Error-logging-and-observation#how-errors-are-logged-and-handled-by-default).

All sample apps have a custom callback that prints WIL logs to stderr.

```c++
inline void set_wil_log_callback() {
    wil::SetResultLoggingCallback([](wil::FailureInfo const& failure) noexcept
        {
            constexpr std::size_t sizeOfLogMessageWithNul = 2048;

            wchar_t logMessage[sizeOfLogMessageWithNul];
            if (SUCCEEDED(wil::GetFailureLogString(logMessage, sizeOfLogMessageWithNul, failure)))
            {
                std::fputws(logMessage, stderr);
            }
        });
}
```
