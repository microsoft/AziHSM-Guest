#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Installs the AziHSM Linux device components from release artifacts, local
# packages, or securely configured packages.microsoft.com sources.

# Future improvements:
#
# 1. Remove the logic that queries both the `testing` suite and the production
#    suites for Ubuntu. Currently, at the time of writing this script, AziHSM
#    packages for Ubuntu are only available in the `testing` suite, so this
#    script currently follows these steps:
#       1. If the production package suite has all the AziHSM packages we need,
#          install from there.
#       2. Otherwise, install from the `testing` suite.

set -euo pipefail

# Installer identity prefixes diagnostics, and `DEFAULT_OS_RELEASE_FILE` feeds
# platform detection unless the environment supplies a testable override.
readonly PROGRAM_NAME="${0##*/}"
readonly DEFAULT_OS_RELEASE_FILE="/etc/os-release"

# Supported distributions are matched by `is_supported_version`; the detected
# release is retained in `PLATFORM_VERSION` for repository construction.
readonly -a SUPPORTED_UBUNTU_VERSIONS=("22.04" "24.04")
readonly -a SUPPORTED_AZURE_LINUX_VERSIONS=("3" "3.*")

# Architecture aliases and ELF identities cover the supported host policy.
readonly -a SUPPORTED_ARCHITECTURE_NAMES=("x86_64" "amd64")
declare -Ar ARCHITECTURE_ALIASES=(
    [x86_64]="x86_64"
    [amd64]="x86_64"
)
declare -Ar ELF_MACHINE_IDENTITIES=(
    [x86_64]="Advanced Micro Devices X86-64"
)

# Repository constants pin the PMC host, Ubuntu signing identity, managed
# destination paths, and Azure Linux channels used by repository setup.
readonly MICROSOFT_PACKAGES_HOST="packages.microsoft.com"
readonly MICROSOFT_SIGNING_KEY_URL="https://${MICROSOFT_PACKAGES_HOST}/keys/microsoft.asc"
readonly MICROSOFT_SIGNING_KEY_FINGERPRINT="BC528686B50D79E339D3721CEB3E94ADBE1229CF"
readonly UBUNTU_MICROSOFT_TESTING_SUITE="testing"
declare -Ar UBUNTU_STABLE_REPOSITORY_SUITES=(
    [22.04]="jammy"
    [24.04]="noble"
)
readonly UBUNTU_MICROSOFT_KEYRING_PATH="${AZIHSM_UBUNTU_KEYRING_PATH:-/usr/share/keyrings/azihsm-microsoft-prod.gpg}"
readonly UBUNTU_MICROSOFT_SOURCE_PATH="${AZIHSM_UBUNTU_SOURCE_PATH:-/etc/apt/sources.list.d/azihsm-microsoft-prod.list}"
readonly UBUNTU_MICROSOFT_PREFERENCES_PATH="${AZIHSM_UBUNTU_PREFERENCES_PATH:-/etc/apt/preferences.d/azihsm-microsoft-prod.pref}"
readonly AZURE_LINUX_MICROSOFT_OSS_REPO_PATH="${AZIHSM_AZURE_LINUX_OSS_REPO_PATH:-/etc/yum.repos.d/azihsm-microsoft-azurelinux3-ms-oss.repo}"
readonly AZURE_LINUX_MICROSOFT_NON_OSS_REPO_PATH="${AZIHSM_AZURE_LINUX_NON_OSS_REPO_PATH:-/etc/yum.repos.d/azihsm-microsoft-azurelinux3-ms-non-oss.repo}"
readonly -a AZURE_LINUX_REPOSITORY_CHANNELS=("ms-oss" "ms-non-oss")

# Globals used to set up the AziHSM guest stack library.
readonly API_LIBRARY_NAME="libazihsm_api_resilient.so"
readonly API_LIBRARY_SONAME="libazihsm_api_resilient.so.1"
readonly API_HEADER_NAME="azihsm_api_resilient.h"

# Package identities define the repository-backed AziHSM stack. Kernel-version
# package names are constructed at their call sites from the applicable family.
readonly UBUNTU_DRIVER_PACKAGE_FAMILY="azihsm-module"
readonly UBUNTU_DRIVER_PACKAGE_GLOB="${UBUNTU_DRIVER_PACKAGE_FAMILY}-*"
readonly UBUNTU_AZURE_DRIVER_PACKAGE="${UBUNTU_DRIVER_PACKAGE_FAMILY}-azure"
readonly UBUNTU_GENERIC_DRIVER_PACKAGE="${UBUNTU_DRIVER_PACKAGE_FAMILY}-generic"
readonly AZURE_LINUX_DRIVER_PACKAGE_FAMILY="azihsm-driver"
readonly API_RUNTIME_PACKAGE="libazihsmr"
declare -Ar API_DEVELOPMENT_PACKAGES=(
    [ubuntu]="${API_RUNTIME_PACKAGE}-dev"
    [azurelinux]="${API_RUNTIME_PACKAGE}-devel"
)
readonly -a UBUNTU_APT_PREFERENCE_PACKAGES=(
    "${UBUNTU_DRIVER_PACKAGE_GLOB}"
    "${API_RUNTIME_PACKAGE}"
    "${API_DEVELOPMENT_PACKAGES[ubuntu]}"
    "libkmpp"
    "libkmpp-dev"
)

# KMPP (Key Management and Protection Platform) package and runtime state.
readonly UBUNTU_KMPP_RUNTIME_PACKAGE="libkmpp"
readonly UBUNTU_KMPP_DEVELOPMENT_PACKAGE="libkmpp-dev"
readonly AZURE_LINUX_KMPP_RUNTIME_PACKAGE="kmpp"
readonly AZURE_LINUX_KMPP_DEVELOPMENT_PACKAGE="kmpp-devel"
readonly KMPP_AZIHSM_BACKEND_BASENAME="libkmpp_azihsm.so"
readonly KMPP_PROVIDER_NAME="kmppprovider"
readonly KMPP_MAIN_UNIT="dbus-com.microsoft.kmpp.service"
readonly KMPP_OPENSSL_MARKER_PATH="${AZIHSM_KMPP_OPENSSL_MARKER_PATH:-/etc/kmpp/disableDefaultProvider}"
readonly KMPP_RUNTIME_CONFIG_PATH="${AZIHSM_KMPP_RUNTIME_CONFIG_PATH:-/var/opt/msft/ap/data/kmpp/config.cnf}"
readonly KMPP_FILESYSTEM_ROOT="${AZIHSM_KMPP_FILESYSTEM_ROOT:-}"
readonly KMPP_SYSTEMD_RUNTIME_DIRECTORY="${AZIHSM_KMPP_SYSTEMD_RUNTIME_DIRECTORY:-/run/systemd/system}"
readonly AZURE_LINUX_KMPP_REPO_PATH="${AZIHSM_AZURE_LINUX_KMPP_REPO_PATH:-/etc/yum.repos.d/azihsm-microsoft-azurelinux3-kmpp.repo}"
readonly AZURE_LINUX_KMPP_REPOSITORY_ID_PREFIX="azurelinux3.0prodms-oss"
SKIP_KMPP=false
KMPP_INSTALL_DEV=false
KMPP_SELECTED_SUITE=""
KMPP_PROVIDER_PATH=""
KMPP_AZIHSM_BACKEND_PATH=""
KMPP_SERVICE_READINESS_DEFERRED=false
KMPP_INSTALLATION_SUPPORTED=false
declare -a KMPP_PACKAGE_FILES=()
declare -a KMPP_PACKAGE_PATHS=()

# Membership in this group grants access to the package-managed /dev/azihsm0 device.
readonly AZIHSM_DEVICE_ACCESS_GROUP="azihsm"
# Membership in this group is consumed by the system TPM device access policy.
readonly TPM_DEVICE_ACCESS_GROUP="tss"
readonly -a DEVICE_ACCESS_GROUPS=(
    "${AZIHSM_DEVICE_ACCESS_GROUP}"
    "${TPM_DEVICE_ACCESS_GROUP}"
)

# Repository bootstrap commands must already exist because package managers
# remain unused until these tools configure and validate trusted PMC sources.
readonly -a REPOSITORY_BOOTSTRAP_COMMANDS=(
    "chmod"
    "chown"
    "cmp"
    "curl"
    "install"
    "mktemp"
    "mv"
    "rm"
    "sleep"
    "tr"
)
readonly -a UBUNTU_REPOSITORY_BOOTSTRAP_COMMANDS=("awk" "dpkg" "gpg")
readonly -a AZURE_LINUX_REPOSITORY_BOOTSTRAP_COMMANDS=()

# Local Ubuntu API artifacts use the conventional system library directory.
readonly UBUNTU_API_LIBRARY_DIRECTORY="${AZIHSM_UBUNTU_API_LIBRARY_DIRECTORY:-/usr/lib}"
# Local Azure Linux API artifacts use the conventional system library directory.
readonly AZURE_LINUX_API_LIBRARY_DIRECTORY="${AZIHSM_AZURE_LINUX_API_LIBRARY_DIRECTORY:-/usr/lib}"
readonly API_INCLUDE_DIRECTORY="${AZIHSM_API_INCLUDE_DIRECTORY:-/usr/include}"
readonly LDCONFIG_PATH="${AZIHSM_LDCONFIG_PATH:-/sbin/ldconfig}"

# Globals for hardened HTTPS downloads.
readonly WEB_REQUEST_MAX_ATTEMPTS=4
readonly WEB_REQUEST_CONNECT_TIMEOUT_SECONDS=15
readonly WEB_REQUEST_MAX_TIME_SECONDS=60
readonly WEB_REQUEST_MAX_REDIRECTS=5
readonly WEB_REQUEST_INITIAL_BACKOFF_SECONDS=1
readonly WEB_REQUEST_MAX_BACKOFF_SECONDS=4
readonly OS_RELEASE_FILE="${AZIHSM_OS_RELEASE_FILE:-${DEFAULT_OS_RELEASE_FILE}}"

# Runtime package mappings support local API validation and archive extraction.
readonly BINUTILS_PACKAGE="binutils"
readonly COREUTILS_PACKAGE="coreutils"
readonly UNZIP_PACKAGE="unzip"
declare -Ar UBUNTU_PREREQUISITE_PACKAGES=(
    [readelf]="${BINUTILS_PACKAGE}"
    [realpath]="${COREUTILS_PACKAGE}"
    [unzip]="${UNZIP_PACKAGE}"
)
declare -Ar AZURE_LINUX_PREREQUISITE_PACKAGES=(
    [readelf]="${BINUTILS_PACKAGE}"
    [realpath]="${COREUTILS_PACKAGE}"
    [unzip]="${UNZIP_PACKAGE}"
)

# Global toggles and variables used throughout this script:
SKIP_DRIVER=false
SKIP_API=false
SKIP_USER_GROUPS=false
USER_GROUPS_ADD_LIST=""
USER_GROUPS_ADD_LIST_PROVIDED=false
API_INSTALL_DEV=false
NORMALIZED_ARCHITECTURE=""
API_STAGED_LIBRARY_PATH=""
API_STAGED_HEADER_PATH=""
API_LIBRARY_MODE=""
API_TRANSACTION_ACTIVE=false
API_PRESERVE_STAGING=false
PLATFORM=""
PLATFORM_VERSION=""
KERNEL_VERSION=""
TEMP_DIR=""
SELECTED_REPOSITORY_DRIVER_PACKAGE=""
SELECTED_UBUNTU_REPOSITORY_SUITE=""
UBUNTU_REPOSITORY_ARCHITECTURE=""
declare -a DRIVER_PACKAGE_PATHS=()
declare -a API_PACKAGE_PATHS=()
declare -a UBUNTU_MISSING_PACKAGE_REQUIREMENTS=()
declare -a USER_GROUP_TARGETS=()
declare -a MISSING_DEVICE_ACCESS_GROUPS=()
declare -a USER_GROUP_MEMBERSHIP_ADDITIONS=()
declare -a API_DESTINATION_STAGING_DIRECTORIES=()
# Parallel transaction arrays describe runtime, optional header, and linker.
declare -a API_ARTIFACT_LABELS=()
declare -a API_ARTIFACT_DESTINATIONS=()
declare -a API_ARTIFACT_STAGED_PATHS=()
declare -a API_ARTIFACT_EXISTING_TYPES=()
declare -a API_ARTIFACT_BACKUPS=()
declare -a API_ARTIFACT_PUBLISHED=()

# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

# Removes temporary download, repository, probe, and extraction artifacts.
cleanup() {
    local staging_directory=""

    # Give an active API transaction its rollback opportunity before removing
    # any workspace paths that may contain its recovery data.
    if declare -F cleanup_local_api_transaction >/dev/null; then
        cleanup_local_api_transaction
    fi

    # Destination-local staging is removed unless failed recovery needs it.
    if [[ "${API_PRESERVE_STAGING}" == false ]]; then
        for staging_directory in "${API_DESTINATION_STAGING_DIRECTORIES[@]}"; do
            if [[ -n "${staging_directory}" && -d "${staging_directory}" ]]; then
                rm -rf -- "${staging_directory}"
            fi
        done
    fi

    # The shared workspace is always disposable at process exit.
    if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
        rm -rf -- "${TEMP_DIR}"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Writes an informational message to standard output.
log_info() {
    printf '%s\n' "$*"
}

# Prints a heading with a title-width dash border.
print_section_header() {
    local title="$1"
    local border=""
    printf -v border '%*s' "${#title}" ""
    border="${border// /-}"
    printf '%s\n%s\n%s\n' "${border}" "${title}" "${border}"
}

# Writes an error message to standard error.
log_error() {
    printf '%s: error: %s\n' "${PROGRAM_NAME}" "$*" >&2
}

# Writes an error and exits.
panic() {
    log_error "$*"
    exit 1
}

# Ensures a required executable can be found.
require_command() {
    local command_name="$1"
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        panic "required command '${command_name}' was not found on PATH"
    fi
}

# Renders an argument array as a shell-safe, reproducible command line.
format_command() {
    local argument=""
    local quoted_argument=""
    local rendered=""

    # Each argument is independently quoted before joining the display string.
    for argument in "$@"; do
        printf -v quoted_argument '%q' "${argument}"
        if [[ -n "${rendered}" ]]; then
            rendered+=" "
        fi
        rendered+="${quoted_argument}"
    done

    # Emit the completed representation as one log-ready line.
    printf '%s\n' "${rendered}"
}

# Logs a command immediately before its caller executes it.
log_command() {
    local rendered=""
    rendered="$(format_command "$@")"
    log_info "Command: ${rendered}"
}

# Logs and executes one command without reinterpreting its argument array.
execute_command() {
    log_command "$@"
    "$@"
}

# Resolves an existing regular file into the caller's output variable.
canonicalize_regular_file() {
    local input_path="$1"
    local description="$2"
    local output_name="$3"
    local resolved_value=""
    local -n output_ref="${output_name}"

    # The caller-provided path must already identify a regular file.
    if [[ ! -f "${input_path}" ]]; then
        panic "${description} is not a regular file: ${input_path}"
    fi

    # Canonical resolution must preserve the regular-file contract.
    require_command realpath
    if ! resolved_value="$(realpath -e -- "${input_path}")"; then
        panic "failed to resolve ${description}: ${input_path}"
    fi
    if [[ ! -f "${resolved_value}" ]]; then
        panic "${description} did not resolve to a regular file: ${input_path}"
    fi

    # Return only the fully validated canonical path.
    output_ref="${resolved_value}"
}

# Returns the supported machine architecture names for user-facing errors.
supported_architecture_names() {
    local IFS="/"
    printf '%s\n' "${SUPPORTED_ARCHITECTURE_NAMES[*]}"
}

# Checks `SUPPORTED_ARCHITECTURE_NAMES` membership across input sources.
is_supported_architecture_name() {
    local architecture="$1"
    local supported_architecture=""

    # Exact membership avoids accepting architecture prefixes or suffixes.
    for supported_architecture in "${SUPPORTED_ARCHITECTURE_NAMES[@]}"; do
        if [[ "${architecture}" == "${supported_architecture}" ]]; then
            return 0
        fi
    done

    # Exhausting the allowlist reports an unsupported architecture.
    return 1
}

# Returns success when the installer process has an effective user ID of zero.
is_running_as_root() {
    [[ "${EUID}" -eq 0 ]]
}

# Stops non-root callers before any setup action occurs.
require_root() {
    if ! is_running_as_root; then
        panic "this installer must be run as root (EUID 0); rerun it from a root shell"
    fi
}

# Removes matching outer quotes from a value read from os-release.
strip_outer_quotes() {
    local value="$1"
    local first=""
    local last=""

    # Boundary characters are captured only for nonempty input.
    if [[ -n "${value}" ]]; then
        first="${value:0:1}"
        last="${value: -1}"
    fi

    # Only matching single- or double-quote pairs are stripped.
    if [[ "${#value}" -ge 2 ]] &&
        { [[ "${first}" == '"' && "${last}" == '"' ]] ||
          [[ "${first}" == "'" && "${last}" == "'" ]]; }; then
        value="${value:1:${#value}-2}"
    fi

    # Emit the normalized value for command-substitution callers.
    printf '%s\n' "${value}"
}

# Initializes the shared `TEMP_DIR` once for cleanup by the EXIT trap.
get_temporary_workspace() {
    local temporary_workspace=""

    # Reusers retain the original workspace and reject externally removed state.
    if [[ -n "${TEMP_DIR}" ]]; then
        if [[ ! -d "${TEMP_DIR}" ]]; then
            panic "temporary workspace is no longer available: ${TEMP_DIR}"
        fi
        return
    fi

    # Publish the new path only after `mktemp` returns an existing directory.
    require_command mktemp
    if ! temporary_workspace="$(mktemp -d)"; then
        panic "failed to create a temporary workspace"
    fi
    if [[ ! -d "${temporary_workspace}" ]]; then
        panic "mktemp did not create the temporary workspace"
    fi

    # Publish and report the workspace only after validation succeeds.
    TEMP_DIR="${temporary_workspace}"
    log_info "Created temporary workspace: ${TEMP_DIR}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

# Shows command-line help.
usage() {
    cat <<EOF
Usage: ${PROGRAM_NAME} [OPTIONS]

Run AziHSM Linux driver setup, API library setup, user group setup, etc.

This script must be run as root (EUID 0).
It does not invoke sudo or otherwise elevate privileges automatically.

This script does the following:

1. Install the AziHSM driver. (Unless --skip-driver is specified.)
   By default, the driver is downloaded from PMC (packages.microsoft.com).
   Local driver packages (*.deb or *.rpm) can be installed instead by specifying --driver-path.
2. Set up user groups to ensure that the AziHSM device can be used without needing root permission.
3. Install the AziHSM API library. (Unless --skip-api is specified.)
   By default, the API library is downloaded from PMC (packages.microsoft.com).
   If --api-install-dev is specified, the development C/C++ header file will be installed as well.
   Local API packages (*.deb or *.rpm) can be installed instead by specifying --api-path.
4. Install the KMPP runtime and optional development package unless skipped.
   Local KMPP packages (*.deb or *.rpm) can be installed instead by specifying --kmpp-path.

Options:
  --driver-path PATH... Install one or more local .deb or .rpm driver packages.
                        May be repeated.
  --api-path PATH...    Install one or more local .deb or .rpm API packages.
                        May be repeated.
  --kmpp-path PATH...   Install one or more local .deb or .rpm KMPP packages.
                        May be repeated.
  --api-install-dev     Install the development package when downloading the API.
  --skip-driver         Skip all driver detection and installation.
  --skip-api            Skip the ${API_LIBRARY_NAME} installation step.
  --skip-kmpp           Skip KMPP repository, installation, and readiness work.
  --kmpp-install-dev    Install KMPP development headers with the full runtime.
  --user-groups-add-list VALUE
                        Add comma-separated users, in addition to a valid
                        non-root SUDO_USER, to the azihsm and tss groups.
  --skip-user-groups    Skip all user discovery and azihsm/tss group setup.
  -h, --help            Show this help and exit.
EOF
}

# Parses options and rejects positional driver package arguments.
parse_arguments() {
    # Every option consumes its own arguments and updates shared installer state.
    while [[ $# -gt 0 ]]; do
        case "$1" in
        --driver-path | --driver-path=* | --api-path | --api-path=* | --kmpp-path | --kmpp-path=*)
            local path_option="${1%%=*}"
            local package_array_name=""
            # Each component retains its own ordered package list.
            case "${path_option}" in
            --driver-path) package_array_name="DRIVER_PACKAGE_PATHS" ;;
            --api-path) package_array_name="API_PACKAGE_PATHS" ;;
            --kmpp-path) package_array_name="KMPP_PACKAGE_PATHS" ;;
            esac
            local -n local_package_paths="${package_array_name}"

            # Both option forms require at least one non-empty package path.
            if [[ "$1" == *=* ]]; then
                local first_path="${1#*=}"
                if [[ -z "${first_path}" ]]; then
                    panic "${path_option} requires a non-empty local package path"
                fi
                local_package_paths+=("${first_path}")
                shift
            else
                shift
                if [[ $# -eq 0 || -z "$1" || "$1" == -* ]]; then
                    panic "${path_option} requires one or more local package paths"
                fi
            fi

            # Collect paths separately until the next option, including repeats.
            while [[ $# -gt 0 && "$1" != -* ]]; do
                if [[ -z "$1" ]]; then
                    panic "${path_option} requires non-empty local package paths"
                fi
                local_package_paths+=("$1")
                shift
            done
            ;;
        --api-install-dev)
            API_INSTALL_DEV=true
            shift
            ;;
        --skip-driver)
            SKIP_DRIVER=true
            shift
            ;;
        --skip-api)
            SKIP_API=true
            shift
            ;;
        --skip-kmpp)
            SKIP_KMPP=true
            shift
            ;;
        --kmpp-install-dev)
            KMPP_INSTALL_DEV=true
            shift
            ;;
        --skip-user-groups)
            SKIP_USER_GROUPS=true
            shift
            ;;
        --user-groups-add-list)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                panic "--user-groups-add-list requires a non-empty comma-separated username list"
            fi
            USER_GROUPS_ADD_LIST="$2"
            USER_GROUPS_ADD_LIST_PROVIDED=true
            shift 2
            ;;
        --user-groups-add-list=*)
            USER_GROUPS_ADD_LIST="${1#*=}"
            if [[ -z "${USER_GROUPS_ADD_LIST}" ]]; then
                panic "--user-groups-add-list requires a non-empty comma-separated username list"
            fi
            USER_GROUPS_ADD_LIST_PROVIDED=true
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            if [[ $# -ne 0 ]]; then
                panic "positional arguments are not supported; use repeatable --driver-path PATH options"
            fi
            return
            ;;
        -*)
            panic "unknown option: $1 (try --help)"
            ;;
        *)
            panic "unexpected positional argument '$1'; use --driver-path PATH for each local driver package"
            ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Runtime prerequisites
# ---------------------------------------------------------------------------

# Maps an inventoried command to its detected-distro package.
prerequisite_package_for_command() {
    local command_name="$1"
    local package_name=""

    # Distribution mappings provide the native package for the missing tool.
    case "${PLATFORM}" in
    ubuntu)
        package_name="${UBUNTU_PREREQUISITE_PACKAGES[${command_name}]:-}"
        ;;
    azurelinux)
        package_name="${AZURE_LINUX_PREREQUISITE_PACKAGES[${command_name}]:-}"
        ;;
    *)
        panic "internal error: prerequisite mapping has no platform"
        ;;
    esac

    # Missing mappings indicate an installer definition error.
    if [[ -z "${package_name}" ]]; then
        panic "internal error: no ${PLATFORM} package maps to required command '${command_name}'"
    fi
    printf '%s\n' "${package_name}"
}

# Installs missing tools, reusing already-refreshed repository metadata.
install_runtime_prerequisites() {
    local repository_metadata_refreshed="${1:-false}"
    local command_name=""
    local package_name=""
    local -a required_commands=()
    local -a missing_packages=()
    local -A selected_packages=()
    # Local package validation requires canonical file paths.
    if [[ "${#DRIVER_PACKAGE_PATHS[@]}" -gt 0 || "${#API_PACKAGE_PATHS[@]}" -gt 0 ||
        "${#KMPP_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        required_commands+=("realpath")
    fi

    # Convert absent commands to unique distro package names for one install.
    for command_name in "${required_commands[@]}"; do
        if command -v "${command_name}" >/dev/null 2>&1; then
            continue
        fi

        # Each missing command maps to one deduplicated native package.
        package_name="$(prerequisite_package_for_command "${command_name}")"
        if [[ -z "${selected_packages[${package_name}]:-}" ]]; then
            missing_packages+=("${package_name}")
            selected_packages["${package_name}"]=true
        fi
    done

    # An empty installation plan leaves package metadata and host state untouched.
    if [[ "${#missing_packages[@]}" -eq 0 ]]; then
        return
    fi

    # Non-PMC runs retain native repository behavior because they consume only
    # base runtime tools, not packages from the managed Microsoft sources.
    case "${PLATFORM}" in
    ubuntu)
        require_command apt-get
        if [[ "${repository_metadata_refreshed}" == false ]]; then
            log_info "Refreshing Ubuntu package metadata for missing installer prerequisites."
            if ! execute_command apt-get update; then
                panic "failed to refresh Ubuntu package metadata for installer prerequisites with 'apt-get update'"
            fi
        fi

        # The complete Ubuntu prerequisite plan is installed in one transaction.
        log_info "Installing missing Ubuntu installer prerequisite package(s): ${missing_packages[*]}"
        if ! execute_command env DEBIAN_FRONTEND=noninteractive \
            apt-get install -y "${missing_packages[@]}"; then
            panic "failed to install Ubuntu installer prerequisite package(s): ${missing_packages[*]}"
        fi
        ;;
    azurelinux)
        require_command tdnf
        log_info "Installing missing Azure Linux installer prerequisite package(s): ${missing_packages[*]}"
        if ! execute_command tdnf install -y "${missing_packages[@]}"; then
            panic "failed to install Azure Linux installer prerequisite package(s): ${missing_packages[*]}"
        fi
        ;;
    *)
        panic "internal error: prerequisite installation has no platform"
        ;;
    esac
}

# ---------------------------------------------------------------------------
# HTTPS helpers
# ---------------------------------------------------------------------------

# Downloads HTTPS content with bounded retries and private attempt-local output.
download_https_file() {
    local url="$1"
    local output_path="$2"
    local request_description="$3"
    local attempt=1
    local backoff_seconds="${WEB_REQUEST_INITIAL_BACKOFF_SECONDS}"
    local attempt_body=""
    local attempt_error=""
    local http_status=""
    local curl_exit=0
    local failure_description=""

    # Requests require HTTPS and the caller-owned private workspace.
    if [[ "${url}" != https://* ]]; then
        panic "refusing to request a non-HTTPS URL"
    fi
    if [[ -z "${TEMP_DIR}" || ! -d "${TEMP_DIR}" ]]; then
        panic "internal error: a temporary workspace is required for web requests"
    fi
    # All tools are resolved before stale output is removed.
    require_command curl
    require_command mktemp
    require_command sleep

    # Stale caller output cannot survive a failed request.
    if ! rm -f -- "${output_path}"; then
        panic "failed to clear stale HTTPS download output"
    fi

    # Each bounded attempt writes private body and diagnostic files.
    while [[ "${attempt}" -le "${WEB_REQUEST_MAX_ATTEMPTS}" ]]; do
        if ! attempt_body="$(mktemp "${TEMP_DIR}/web-response.XXXXXX")"; then
            panic "failed to create temporary HTTPS download output"
        fi
        if ! attempt_error="$(mktemp "${TEMP_DIR}/web-error.XXXXXX")"; then
            panic "failed to create temporary HTTPS download output"
        fi

        # Curl enforces HTTPS redirects, TLS, time, and redirect bounds.
        log_info "HTTPS download ${request_description}: attempt ${attempt}/${WEB_REQUEST_MAX_ATTEMPTS}."
        if http_status="$(curl \
            --fail --location --silent \
            --retry 0 \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout "${WEB_REQUEST_CONNECT_TIMEOUT_SECONDS}" \
            --max-time "${WEB_REQUEST_MAX_TIME_SECONDS}" \
            --max-redirs "${WEB_REQUEST_MAX_REDIRECTS}" \
            --output "${attempt_body}" \
            --write-out '%{http_code}' \
            "${url}" 2>"${attempt_error}")"; then
            curl_exit=0
        else
            curl_exit=$?
        fi

        # Only a successful curl exit with a 2xx status publishes output.
        if [[ "${curl_exit}" -eq 0 &&
            "${http_status}" =~ ^2[0-9]{2}$ ]]; then
            if ! mv -- "${attempt_body}" "${output_path}"; then
                panic "failed to promote completed HTTPS download output"
            fi
            rm -f -- "${attempt_error}"
            return 0
        fi

        # Diagnostics distinguish HTTP responses from transport failures.
        if [[ "${http_status}" =~ ^[0-9]{3}$ &&
            "${http_status}" != "000" ]]; then
            failure_description="HTTP ${http_status}"
        else
            failure_description="network error ${curl_exit}"
        fi

        # Failed attempt artifacts are removed before retry or return.
        rm -f -- "${attempt_body}" "${attempt_error}"
        if [[ "${attempt}" -eq "${WEB_REQUEST_MAX_ATTEMPTS}" ]]; then
            log_error "HTTPS download ${request_description} failed (${failure_description}); attempts exhausted."
            return 1
        fi

        # Retry delay grows exponentially up to the configured ceiling.
        log_error "HTTPS download ${request_description} failed (${failure_description}); retrying in ${backoff_seconds}s."
        sleep "${backoff_seconds}"
        if [[ "${backoff_seconds}" -lt "${WEB_REQUEST_MAX_BACKOFF_SECONDS}" ]]; then
            backoff_seconds=$((backoff_seconds * 2))
            if [[ "${backoff_seconds}" -gt "${WEB_REQUEST_MAX_BACKOFF_SECONDS}" ]]; then
                backoff_seconds="${WEB_REQUEST_MAX_BACKOFF_SECONDS}"
            fi
        fi
        attempt=$((attempt + 1))
    done

    # Defensive fallback preserves failure if loop control changes later.
    return 1
}

# ---------------------------------------------------------------------------
# Kernel and operating-system detection
# ---------------------------------------------------------------------------

# Normalizes the machine architecture using the centralized supported aliases.
detect_supported_architecture() {
    local reported_architecture=""
    local architecture_key=""

    # The kernel-reported machine value is the architecture source of truth.
    require_command uname
    if ! reported_architecture="$(uname -m)"; then
        panic "failed to detect the machine architecture with 'uname -m'"
    fi

    # Supported aliases normalize to one repository architecture.
    architecture_key="${reported_architecture,,}"
    if ! is_supported_architecture_name "${architecture_key}"; then
        panic "This script does not support architecture '${reported_architecture}'; supported values are $(supported_architecture_names)."
    fi
    NORMALIZED_ARCHITECTURE="${ARCHITECTURE_ALIASES[${architecture_key}]:-}"
    if [[ -z "${NORMALIZED_ARCHITECTURE}" ]]; then
        panic "internal error: no normalized architecture mapping exists for supported architecture '${reported_architecture}'"
    fi
    if ! is_supported_architecture_name "${NORMALIZED_ARCHITECTURE}"; then
        panic "internal error: normalized architecture '${NORMALIZED_ARCHITECTURE}' is not in SUPPORTED_ARCHITECTURE_NAMES"
    fi

    # Detection output includes both source and normalized values.
    log_info "Detected machine architecture: '${reported_architecture}', normalized to: '${NORMALIZED_ARCHITECTURE}'."
}

# Detects and validates the running kernel release.
detect_kernel() {
    # The running kernel release determines kernel-specific package names.
    require_command uname

    # Kernel detection must return one nonempty package-safe release string.
    if ! KERNEL_VERSION="$(uname -r)"; then
        panic "failed to detect the running kernel with 'uname -r'"
    fi
    if [[ -z "${KERNEL_VERSION}" ]]; then
        panic "'uname -r' returned an empty kernel version"
    fi
    if [[ ! "${KERNEL_VERSION}" =~ ^[A-Za-z0-9._+-]+$ ]]; then
        panic "'uname -r' returned an invalid kernel version: ${KERNEL_VERSION}"
    fi

    # A validated release is safe to embed in package identifiers.
    log_info "Detected kernel ${KERNEL_VERSION}."
}

# Matches exact or trailing-wildcard supported-version entries.
is_supported_version() {
    local version="$1"
    shift
    local supported_version=""

    # Entries support exact matches or one trailing wildcard prefix.
    for supported_version in "$@"; do
        if [[ "${supported_version}" == *"*" &&
            "${version}" == "${supported_version%\*}"* ]]; then
            return 0
        fi
        if [[ "${version}" == "${supported_version}" ]]; then
            return 0
        fi
    done

    # Exhausting all supported entries reports a version mismatch.
    return 1
}

# Detects and validates the supported Linux distribution.
detect_platform() {
    local line=""
    local key=""
    local value=""
    local os_id=""
    local version_id=""

    # Platform detection consumes a readable os-release source.
    if [[ ! -r "${OS_RELEASE_FILE}" ]]; then
        panic "cannot read OS release information from ${OS_RELEASE_FILE}"
    fi

    # Parse only the two os-release keys consumed by platform selection.
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        if [[ "${line}" != *=* ]]; then
            continue
        fi

        # Valid assignment lines are split before supported keys are selected.
        key="${line%%=*}"
        value="$(strip_outer_quotes "${line#*=}")"
        case "${key}" in
        ID)
            os_id="${value,,}"
            ;;
        VERSION_ID)
            version_id="${value}"
            ;;
        esac
    done <"${OS_RELEASE_FILE}"

    # Both required keys must be present after parsing.
    if [[ -z "${os_id}" ]]; then
        panic "${OS_RELEASE_FILE} does not define ID"
    fi
    if [[ -z "${version_id}" ]]; then
        panic "${OS_RELEASE_FILE} does not define VERSION_ID"
    fi

    # Distribution-specific version policy sets normalized global state.
    case "${os_id}" in
    ubuntu)
        if is_supported_version \
            "${version_id}" "${SUPPORTED_UBUNTU_VERSIONS[@]}"; then
            PLATFORM="ubuntu"
            PLATFORM_VERSION="${version_id}"
        else
            panic "unsupported Ubuntu version '${version_id}'; supported versions are 22.04 and 24.04"
        fi
        ;;
    azurelinux)
        if is_supported_version \
            "${version_id}" "${SUPPORTED_AZURE_LINUX_VERSIONS[@]}"; then
            PLATFORM="azurelinux"
            PLATFORM_VERSION="${version_id}"
        else
            panic "unsupported Azure Linux version '${version_id}'; supported version is 3"
        fi
        ;;
    *)
        panic "unsupported Linux distribution '${os_id}' (VERSION_ID='${version_id}'); supported distributions are Ubuntu 22.04/24.04 and Azure Linux 3"
        ;;
    esac

    # The accepted distribution and release are published to the caller.
    log_info "Detected ${os_id} ${version_id}."
}

# ---------------------------------------------------------------------------
# Package repository configuration
# ---------------------------------------------------------------------------

# Verifies repository bootstrap tools without using an unconfigured manager.
validate_repository_bootstrap_prerequisites() {
    local command_name=""
    local -a platform_commands=()

    # Platform-specific bootstrap tools supplement the shared inventory.
    case "${PLATFORM}" in
    ubuntu)
        platform_commands=("${UBUNTU_REPOSITORY_BOOTSTRAP_COMMANDS[@]}")
        ;;
    azurelinux)
        platform_commands=("${AZURE_LINUX_REPOSITORY_BOOTSTRAP_COMMANDS[@]}")
        ;;
    *)
        panic "internal error: repository bootstrap validation has no platform"
        ;;
    esac

    # Bootstrap tools must preexist because repositories are not trusted yet.
    for command_name in \
        "${REPOSITORY_BOOTSTRAP_COMMANDS[@]}" \
        "${platform_commands[@]}"; do
        if ! command -v "${command_name}" >/dev/null 2>&1; then
            panic "repository bootstrap requires command '${command_name}' on PATH; install it from trusted media or the base image and retry because the installer will not use an unconfigured package manager to install bootstrap tools"
        fi
    done
}

# Validates the fixed inputs used for managed-file publication.
validate_managed_file_publication() {
    local staged_path="$1"
    local destination_path="$2"
    local description="$3"
    local destination_directory="${destination_path%/*}"

    # Publication accepts a regular staged file and an existing destination directory.
    if [[ ! -f "${staged_path}" || -L "${staged_path}" ]]; then
        panic "staged ${description} is not a regular file"
    fi
    if [[ ! -d "${destination_directory}" ]]; then
        panic "destination directory for ${description} does not exist: ${destination_directory}"
    fi
}

# Atomically publishes trusted staged content at a managed destination.
publish_managed_file() {
    local staged_path="$1"
    local destination_path="$2"
    local description="$3"
    local action="$4"
    local destination_directory="${destination_path%/*}"
    local destination_name="${destination_path##*/}"
    local atomic_path=""

    # Fixed inputs and a destination-local temporary file precede publication.
    validate_managed_file_publication \
        "${staged_path}" "${destination_path}" "${description}"
    require_command mktemp
    if ! atomic_path="$(mktemp "${destination_directory}/.${destination_name}.XXXXXX")"; then
        panic "failed to create an atomic staging file for ${description}"
    fi
    # Trusted content receives final ownership and mode before atomic rename.
    if ! install -o root -g root -m 0644 -- "${staged_path}" "${atomic_path}"; then
        rm -f -- "${atomic_path}"
        panic "failed to stage managed ${description}"
    fi
    if ! mv -fT -- "${atomic_path}" "${destination_path}"; then
        rm -f -- "${atomic_path}"
        panic "failed to atomically install managed ${description}"
    fi
    # A successful rename is the publication boundary.
    log_info "${action} managed ${description}: ${destination_path}"
}

# Installs trusted staged content, reusing only exact managed content.
install_managed_file() {
    local staged_path="$1"
    local destination_path="$2"
    local description="$3"

    # Fixed staged and destination inputs are validated once up front.
    validate_managed_file_publication \
        "${staged_path}" "${destination_path}" "${description}"
    # Existing managed entries are accepted only when regular and byte-identical.
    if [[ -e "${destination_path}" || -L "${destination_path}" ]]; then
        if [[ ! -f "${destination_path}" || -L "${destination_path}" ]]; then
            panic "managed ${description} is not a regular file: ${destination_path}"
        fi
        if cmp -s -- "${staged_path}" "${destination_path}"; then
            if ! chown root:root -- "${destination_path}"; then
                panic "failed to enforce root ownership and mode 0644 on ${description}"
            fi
            if ! chmod 0644 -- "${destination_path}"; then
                panic "failed to enforce root ownership and mode 0644 on ${description}"
            fi
            log_info "Reusing unchanged managed ${description}: ${destination_path}"
            return
        fi
        panic "managed ${description} has unexpected content; inspect or remove ${destination_path} before retrying"
    fi

    # An absent destination is installed through the atomic publication helper.
    publish_managed_file \
        "${staged_path}" "${destination_path}" "${description}" "Installed"
}

# Returns the stable PMC suite mapped to the detected Ubuntu release.
ubuntu_stable_repository_suite() {
    local stable_suite="${UBUNTU_STABLE_REPOSITORY_SUITES[${PLATFORM_VERSION}]:-}"
    if [[ -z "${stable_suite}" ]]; then
        panic "internal error: no stable Microsoft repository suite maps to Ubuntu ${PLATFORM_VERSION}"
    fi
    printf '%s\n' "${stable_suite}"
}

# Pins and installs the PMC key used by the managed APT source.
configure_ubuntu_microsoft_keyring() {
    local downloaded_key="${TEMP_DIR}/microsoft.asc"
    local staged_keyring="${TEMP_DIR}/azihsm-microsoft-prod.gpg"
    local primary_fingerprint=""
    local fingerprint_count=0
    # Store the downloaded key in the shared workspace for isolated validation.
    require_command gpg
    if ! download_https_file \
        "${MICROSOFT_SIGNING_KEY_URL}" \
        "${downloaded_key}" \
        "Microsoft package signing key"; then
        panic "failed to download the Microsoft package signing key"
    fi

    # Extract every primary-key fingerprint and require the single pinned value.
    if ! primary_fingerprint="$(
        gpg --batch --with-colons --show-keys -- "${downloaded_key}" |
            awk -F: '
                $1 == "pub" { need_fingerprint = 1; next }
                need_fingerprint && $1 == "fpr" {
                    print $10
                    need_fingerprint = 0
                }
            '
    )"; then
        panic "failed to inspect the Microsoft package signing key"
    fi
    fingerprint_count="$(awk 'NF { count++ } END { print count + 0 }' <<<"${primary_fingerprint}")"
    if [[ "${fingerprint_count}" -ne 1 ||
        "${primary_fingerprint}" != "${MICROSOFT_SIGNING_KEY_FINGERPRINT}" ]]; then
        panic "Microsoft package signing key fingerprint verification failed"
    fi

    # Convert the verified key to APT's keyring format before managed install.
    if ! gpg --batch --yes --dearmor \
        --output "${staged_keyring}" -- "${downloaded_key}"; then
        panic "failed to dearmor the verified Microsoft package signing key"
    fi
    install_managed_file \
        "${staged_keyring}" \
        "${UBUNTU_MICROSOFT_KEYRING_PATH}" \
        "AziHSM Microsoft keyring"
}

# Installs the suite-neutral origin policy used by the managed APT source.
configure_ubuntu_preferences() {
    local staged_preferences="${TEMP_DIR}/azihsm-microsoft-prod.pref"
    local package_field="${UBUNTU_APT_PREFERENCE_PACKAGES[*]}"

    # PMC packages are allowlisted above the low catch-all origin priority.
    printf '%s\n' \
        "Package: ${package_field}" \
        "Pin: origin ${MICROSOFT_PACKAGES_HOST}" \
        'Pin-Priority: 500' \
        '' \
        'Package: *' \
        "Pin: origin ${MICROSOFT_PACKAGES_HOST}" \
        'Pin-Priority: 1' \
        >"${staged_preferences}"

    # The validated policy is installed at the managed APT destination.
    install_managed_file \
        "${staged_preferences}" \
        "${UBUNTU_MICROSOFT_PREFERENCES_PATH}" \
        "AziHSM Microsoft APT preferences"
}

# Returns the validated Ubuntu package architecture for repository sources.
ubuntu_repository_architecture() {
    local architecture=""
    local normalized_architecture=""
    # Require dpkg's package architecture to normalize to the detected machine.
    require_command dpkg
    if ! architecture="$(dpkg --print-architecture)"; then
        panic "failed to determine the Ubuntu package architecture"
    fi
    architecture="${architecture,,}"
    if ! is_supported_architecture_name "${architecture}"; then
        panic "unsupported Ubuntu package architecture '${architecture}'; supported values are $(supported_architecture_names)"
    fi
    normalized_architecture="${ARCHITECTURE_ALIASES[${architecture}]:-}"
    if [[ -z "${normalized_architecture}" ||
        "${normalized_architecture}" != "${NORMALIZED_ARCHITECTURE}" ]]; then
        panic "Ubuntu package architecture '${architecture}' does not match the normalized machine architecture '${NORMALIZED_ARCHITECTURE}'"
    fi
    printf '%s\n' "${architecture}"
}

# Writes the one current-format Ubuntu source for a validated suite.
write_ubuntu_repository_source() {
    local destination_path="$1"
    local suite="$2"
    local architecture="$3"
    local stable_suite=""

    # Only the mapped stable suite and shared testing suite are valid inputs.
    stable_suite="$(ubuntu_stable_repository_suite)"
    if [[ "${suite}" != "${stable_suite}" &&
        "${suite}" != "${UBUNTU_MICROSOFT_TESTING_SUITE}" ]]; then
        panic "internal error: unsupported Ubuntu repository suite '${suite}'"
    fi

    # The source binds package architecture, pinned keyring, release, and suite.
    printf 'deb [arch=%s signed-by=%s] https://%s/ubuntu/%s/prod %s main\n' \
        "${architecture}" \
        "${UBUNTU_MICROSOFT_KEYRING_PATH}" \
        "${MICROSOFT_PACKAGES_HOST}" \
        "${PLATFORM_VERSION}" \
        "${suite}" >"${destination_path}"
}

# Publishes an Ubuntu source only when absent, unchanged, or the exact current
# canonical source for the other permitted stable/testing suite.
install_ubuntu_repository_source() {
    local staged_path="$1"
    local suite="$2"
    local architecture="$3"
    local stable_suite=""
    local alternate_suite=""
    local alternate_source="${TEMP_DIR}/azihsm-microsoft-prod-alternate.list"
    local description="AziHSM Microsoft APT source"

    # The alternate canonical source permits safe stable/testing transitions.
    stable_suite="$(ubuntu_stable_repository_suite)"
    if [[ "${suite}" == "${stable_suite}" ]]; then
        alternate_suite="${UBUNTU_MICROSOFT_TESTING_SUITE}"
    elif [[ "${suite}" == "${UBUNTU_MICROSOFT_TESTING_SUITE}" ]]; then
        alternate_suite="${stable_suite}"
    else
        panic "internal error: unsupported Ubuntu repository suite '${suite}'"
    fi
    # Both candidate contents and publication inputs are prepared before mutation.
    write_ubuntu_repository_source \
        "${alternate_source}" "${alternate_suite}" "${architecture}"
    validate_managed_file_publication \
        "${staged_path}" "${UBUNTU_MICROSOFT_SOURCE_PATH}" "${description}"

    # Existing sources must match the selected or alternate canonical content.
    if [[ -e "${UBUNTU_MICROSOFT_SOURCE_PATH}" ||
        -L "${UBUNTU_MICROSOFT_SOURCE_PATH}" ]]; then
        if [[ ! -f "${UBUNTU_MICROSOFT_SOURCE_PATH}" ||
            -L "${UBUNTU_MICROSOFT_SOURCE_PATH}" ]]; then
            panic "managed ${description} is not a regular file: ${UBUNTU_MICROSOFT_SOURCE_PATH}"
        fi
        if cmp -s -- "${staged_path}" "${UBUNTU_MICROSOFT_SOURCE_PATH}"; then
            if ! chown root:root -- "${UBUNTU_MICROSOFT_SOURCE_PATH}"; then
                panic "failed to enforce root ownership and mode 0644 on ${description}"
            fi
            if ! chmod 0644 -- "${UBUNTU_MICROSOFT_SOURCE_PATH}"; then
                panic "failed to enforce root ownership and mode 0644 on ${description}"
            fi
            log_info "Reusing unchanged managed ${description}: ${UBUNTU_MICROSOFT_SOURCE_PATH}"
            return
        fi
        if ! cmp -s -- "${alternate_source}" "${UBUNTU_MICROSOFT_SOURCE_PATH}"; then
            panic "managed ${description} has unexpected content; inspect or remove ${UBUNTU_MICROSOFT_SOURCE_PATH} before retrying"
        fi
        # Canonical alternate content is replaced atomically with the selection.
        publish_managed_file \
            "${staged_path}" \
            "${UBUNTU_MICROSOFT_SOURCE_PATH}" \
            "${description}" \
            "Updated"
        return
    fi

    # An absent source is installed atomically from validated staged content.
    publish_managed_file \
        "${staged_path}" \
        "${UBUNTU_MICROSOFT_SOURCE_PATH}" \
        "${description}" \
        "Installed"
}

# Atomically enables one Ubuntu PMC suite.
configure_ubuntu_repository_suite() {
    local suite="$1"
    local architecture="${2:-}"
    local staged_source="${TEMP_DIR}/azihsm-microsoft-prod.list"

    # Callers may reuse an already validated package architecture.
    if [[ -z "${architecture}" ]]; then
        architecture="$(ubuntu_repository_architecture)"
    fi

    # Canonical content is written and safely transitioned into place.
    write_ubuntu_repository_source "${staged_source}" "${suite}" "${architecture}"
    install_ubuntu_repository_source \
        "${staged_source}" "${suite}" "${architecture}"
}

# Installs Ubuntu trust and policy before enabling the mapped stable suite.
configure_ubuntu_repositories() {
    local architecture=""
    local stable_suite=""

    # Architecture and stable suite selection precede trust publication.
    architecture="$(ubuntu_repository_architecture)"
    UBUNTU_REPOSITORY_ARCHITECTURE="${architecture}"
    stable_suite="$(ubuntu_stable_repository_suite)"
    # Keyring and pin policy are installed before enabling the source.
    configure_ubuntu_microsoft_keyring
    configure_ubuntu_preferences
    log_info "Configuring Ubuntu stable AziHSM repository suite '${stable_suite}'."
    configure_ubuntu_repository_suite "${stable_suite}" "${architecture}"
}

# Strictly validates and installs one PMC Azure Linux channel source.
configure_azurelinux_repository_source() {
    local channel="$1"
    local destination_path="$2"
    local tier="${3:-preview}"
    local architecture="${NORMALIZED_ARCHITECTURE}"
    local repository_id=""
    local repository_root=""
    local repository_url=""
    local tier_label=""
    local downloaded_repo="${TEMP_DIR}/azurelinux-${channel}-config.repo"
    local expected_repo="${TEMP_DIR}/azurelinux-${channel}-expected.repo"
    # Constrain both URL components to installer-owned architecture/channel data.
    if ! is_supported_architecture_name "${architecture}"; then
        panic "unsupported normalized Azure Linux package architecture '${architecture}'; supported values are $(supported_architecture_names)"
    fi
    if ! is_supported_version "${channel}" "${AZURE_LINUX_REPOSITORY_CHANNELS[@]}"; then
        panic "internal error: unsupported Azure Linux repository channel '${channel}'"
    fi

    # Derive the expected repository identity and download URL from that data.
    if [[ "${tier}" != "preview" && "${tier}" != "prod" ]]; then
        panic "internal error: unsupported Azure Linux repository tier '${tier}'"
    fi
    if [[ "${tier}" != "preview" ]]; then
        tier_label="${tier}/"
    fi
    repository_id="azurelinux3.0${tier}${channel}${architecture}"
    repository_root="https://${MICROSOFT_PACKAGES_HOST}/azurelinux/3.0/${tier}/${channel}/${architecture}"
    repository_url="${repository_root}/config.repo"

    # Download the publisher's source into the shared validation workspace.
    if ! download_https_file \
        "${repository_url}" \
        "${downloaded_repo}" \
        "Azure Linux 3 ${tier_label}${channel} repository configuration"; then
        panic "failed to download the Azure Linux 3 ${tier_label}${channel} repository configuration"
    fi
    # Require exact signed-repository settings before managed installation.
    printf '[%s]\nname=azurelinux/3.0/%s/%s/%s\nbaseurl=%s/\ngpgcheck=1\nrepo_gpgcheck=1\nenabled=1\ngpgkey=%s/repodata/repomd.xml.key\n' \
        "${repository_id}" \
        "${tier}" \
        "${channel}" \
        "${architecture}" \
        "${repository_root}" \
        "${repository_root}" >"${expected_repo}"
    if ! cmp -s -- "${expected_repo}" "${downloaded_repo}"; then
        panic "downloaded Azure Linux 3 ${tier_label}${channel} repository configuration failed strict AziHSM validation"
    fi
    install_managed_file \
        "${downloaded_repo}" \
        "${destination_path}" \
        "AziHSM Microsoft Azure Linux 3 ${tier_label}${channel} repository"
}

# Installs both validated PMC Azure Linux channel sources.
configure_azurelinux_repositories() {
    # Both preview channels are required for the AziHSM stack.
    configure_azurelinux_repository_source \
        "ms-oss" \
        "${AZURE_LINUX_MICROSOFT_OSS_REPO_PATH}"
    configure_azurelinux_repository_source \
        "ms-non-oss" \
        "${AZURE_LINUX_MICROSOFT_NON_OSS_REPO_PATH}"
}

# Checks whether driver resolution requires package repositories.
driver_uses_package_repositories() {
    [[ "${SKIP_DRIVER}" == false &&
        "${#DRIVER_PACKAGE_PATHS[@]}" -eq 0 ]]
}

# Checks whether the enabled API requires package repositories.
api_uses_package_repositories() {
    [[ "${SKIP_API}" == false && "${#API_PACKAGE_PATHS[@]}" -eq 0 ]]
}

# Checks whether enabled KMPP installation needs repository selection.
kmpp_uses_package_repositories() {
    [[ "${SKIP_KMPP}" == false && "${#KMPP_PACKAGE_PATHS[@]}" -eq 0 ]]
}

# Checks whether any enabled operation requires package repositories.
repositories_needed() {
    driver_uses_package_repositories ||
        api_uses_package_repositories ||
        kmpp_uses_package_repositories
}

# Installs trust and source files without refreshing package metadata.
configure_repositories() {
    # Repository artifacts share one private staging workspace.
    get_temporary_workspace

    # Platform configuration publishes only installer-managed Microsoft sources.
    case "${PLATFORM}" in
    ubuntu)
        configure_ubuntu_repositories
        ;;
    azurelinux)
        configure_azurelinux_repositories
        if kmpp_uses_package_repositories; then
            configure_azurelinux_repository_source \
                "ms-oss" "${AZURE_LINUX_KMPP_REPO_PATH}" "prod"
        fi
        ;;
    *)
        panic "internal error: repository configuration has no platform"
        ;;
    esac
}

# Refreshes configured repository metadata before package operations.
refresh_repository_metadata() {
    # Native managers refresh only after managed repository publication.
    case "${PLATFORM}" in
    ubuntu)
        require_command apt-get
        log_info "Refreshing Ubuntu package metadata after configuring the AziHSM Microsoft repository."
        if ! execute_command apt-get update; then
            panic "failed to refresh Ubuntu package metadata after configuring the AziHSM Microsoft repository"
        fi
        ;;
    azurelinux)
        # Discard cached state before making both managed channels queryable.
        require_command tdnf
        log_info "Refreshing Azure Linux package metadata after configuring the AziHSM Microsoft repositories."
        if ! execute_command tdnf clean all; then
            panic "failed to clean Azure Linux package metadata with 'tdnf clean all'"
        fi
        if ! execute_command tdnf makecache; then
            panic "failed to refresh the AziHSM Microsoft repository with 'tdnf makecache'"
        fi
        ;;
    *)
        panic "internal error: repository metadata refresh has no platform"
        ;;
    esac
}

# ---------------------------------------------------------------------------
# Driver installation
# ---------------------------------------------------------------------------

# Validates and canonicalizes every local package before any is installed.
validate_local_packages() {
    local -n package_paths="${1:-DRIVER_PACKAGE_PATHS}"
    local description="${2:-local driver package}"
    local expected_extension=""
    local package_path=""
    local canonical_path=""
    local -a canonical_paths=()

    # Distribution identity selects the required local package format.
    case "${PLATFORM}" in
    ubuntu)
        expected_extension=".deb"
        ;;
    azurelinux)
        expected_extension=".rpm"
        ;;
    *)
        panic "internal error: local package validation has no platform"
        ;;
    esac

    # Every input is canonicalized and validated before replacing shared state.
    for package_path in "${package_paths[@]}"; do
        canonicalize_regular_file \
            "${package_path}" "${description}" canonical_path
        if [[ "${package_path,,}" != *"${expected_extension}" ||
            "${canonical_path,,}" != *"${expected_extension}" ]]; then
            panic "${description} '${package_path}' must use the ${expected_extension} format on ${PLATFORM}"
        fi
        canonical_paths+=("${canonical_path}")
        log_info "Validated ${description}: ${canonical_path}"
    done

    # Downstream installation consumes only validated canonical paths.
    package_paths=("${canonical_paths[@]}")
}

# Installs all validated local packages in one native package-tool invocation.
install_local_packages() {
    local -n package_paths="${1:-DRIVER_PACKAGE_PATHS}"
    local description="${2:-AziHSM driver}"
    local -a install_command=()
    local -a full_command=()

    # The native package tool and non-upgrading invocation are platform-specific.
    case "${PLATFORM}" in
    ubuntu)
        require_command dpkg
        install_command=(dpkg --install --)
        ;;
    azurelinux)
        require_command rpm
        install_command=(rpm --upgrade --replacepkgs --)
        ;;
    *)
        panic "internal error: local package installation has no platform"
        ;;
    esac

    # One logged invocation installs the complete validated package set.
    full_command=("${install_command[@]}" "${package_paths[@]}")
    log_info "Installing ${#package_paths[@]} local ${description} package(s)."
    if ! execute_command "${full_command[@]}"; then
        panic "failed to install local ${description} package(s) with ${install_command[0]}"
    fi
}

# Accepts only one recognized absence line with the other stream empty.
is_clean_package_absence() {
    local output_path="$1"
    local error_path="$2"
    shift 2
    local recognized_line=""
    local -a output_lines=()
    local -a error_lines=()

    # Both query streams are loaded without command-substitution newline loss.
    mapfile -t output_lines <"${output_path}"
    mapfile -t error_lines <"${error_path}"

    # A recognized line must be the sole content of exactly one stream.
    for recognized_line in "$@"; do
        if [[ "${#output_lines[@]}" -eq 1 &&
            "${output_lines[0]}" == "${recognized_line}" &&
            "${#error_lines[@]}" -eq 0 ]]; then
            return 0
        fi
        if [[ "${#error_lines[@]}" -eq 1 &&
            "${error_lines[0]}" == "${recognized_line}" &&
            "${#output_lines[@]}" -eq 0 ]]; then
            return 0
        fi
    done
    return 1
}

# Produces bounded printable package-query diagnostics.
package_query_diagnostic() {
    local stream_path=""
    local line=""
    local summary=""
    local truncated=false
    local index=0
    local -a summaries=()
    local -a lines=()

    # Apply identical bounded, printable summarization to stdout and stderr.
    for stream_path in "$1" "$2"; do
        lines=()
        summary=""
        truncated=false
        mapfile -t -n 5 lines < <(
            LC_ALL=C tr -c '\11\12\15\40-\176' '?' <"${stream_path}"
        )
        # At most four sanitized lines and 480 characters enter diagnostics.
        if [[ "${#lines[@]}" -gt 4 ]]; then
            truncated=true
        fi
        for ((index = 0; index < ${#lines[@]} && index < 4; index++)); do
            line="${lines[index]}"
            summary+="${summary:+ | }${line}"
        done
        summary="${summary//$'\r'/ }"
        summary="${summary//$'\t'/ }"
        if [[ "${#summary}" -gt 480 ]]; then
            truncated=true
            summary="${summary:0:480}"
        fi
        if [[ "${truncated}" == true ]]; then
            summary+=" ... (truncated)"
        fi
        summaries+=("${summary}")
    done
    # Labeled streams retain enough context without emitting control bytes.
    printf "stdout='%s'; stderr='%s'" "${summaries[0]}" "${summaries[1]}"
}

# Trims leading and trailing whitespace from a Madison field.
trim_whitespace() {
    local value="$1"
    local output_name="$2"
    local -n output_ref="${output_name}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    output_ref="${value}"
}

# Parses one nonempty three-field `apt-cache madison` row.
parse_madison_row() {
    local line="$1"
    local package_output_name="$2"
    local version_output_name="$3"
    local source_output_name="$4"
    local remainder=""
    local parsed_package=""
    local parsed_version=""
    local parsed_source=""

    # Exactly two separators divide package, version, and source fields.
    if [[ "${line}" != *"|"* ]]; then
        return 1
    fi
    parsed_package="${line%%|*}"
    remainder="${line#*|}"
    if [[ "${remainder}" != *"|"* ]]; then
        return 1
    fi
    parsed_version="${remainder%%|*}"
    parsed_source="${remainder#*|}"
    if [[ "${parsed_source}" == *"|"* ]]; then
        return 1
    fi
    # Field whitespace is normalized before nonempty validation.
    trim_whitespace "${parsed_package}" parsed_package
    trim_whitespace "${parsed_version}" parsed_version
    trim_whitespace "${parsed_source}" parsed_source
    if [[ -z "${parsed_package}" || -z "${parsed_version}" ||
        -z "${parsed_source}" ]]; then
        return 1
    fi

    # Validated fields are published through caller-selected output names.
    printf -v "${package_output_name}" '%s' "${parsed_package}"
    printf -v "${version_output_name}" '%s' "${parsed_version}"
    printf -v "${source_output_name}" '%s' "${parsed_source}"
}

# Runs a fixed metadata query, allowing only an exact clean miss.
repository_package_available() {
    local package_name="$1"
    local ubuntu_suite="${2:-}"
    local azure_repository_id="${2:-}"
    local ubuntu_source_path="${3:-}"
    local ubuntu_lists_path="${4:-}"
    local probe_output=""
    local probe_error=""
    local nul_stripped_output=""
    local probe_status=0
    local probe_diagnostic=""
    local expected_source=""
    local row=""
    local row_package=""
    local row_version=""
    local row_source=""
    local found=false
    local malformed=false
    local clean_status=0
    local absence_line=""
    local failure_prefix=""
    local -a probe_command=()

    # Platform-specific probes retain raw output for strict validation.
    case "${PLATFORM}" in
    ubuntu)
        probe_output="${TEMP_DIR}/apt-cache-madison-${package_name}.out"
        probe_error="${TEMP_DIR}/apt-cache-madison-${package_name}.err"
        failure_prefix="failed to query Ubuntu package metadata for '${package_name}' (apt-cache status"
        if [[ -z "${ubuntu_suite}" ||
            -z "${UBUNTU_REPOSITORY_ARCHITECTURE}" ]]; then
            panic "internal error: Ubuntu package availability requires an active suite and architecture"
        fi
        require_command apt-cache
        # `madison` lists repository-indexed versions and excludes dpkg's
        # installed-only status records. Validate its source column so a
        # package from another configured repository or suite cannot satisfy
        # the currently enabled managed PMC source.
        if [[ -n "${ubuntu_source_path}" ]]; then
            probe_command=(env LC_ALL=C apt-cache \
                -o "Dir::Etc::sourcelist=${ubuntu_source_path}" \
                -o "Dir::Etc::sourceparts=-")
            if [[ -n "${ubuntu_lists_path}" ]]; then
                probe_command+=(-o "Dir::State::lists=${ubuntu_lists_path}")
            fi
            probe_command+=(madison -- "${package_name}")
        else
            probe_command=(env LC_ALL=C apt-cache madison -- "${package_name}")
        fi

        # Keep command logging outside captured query output.
        log_command "${probe_command[@]}"
        if "${probe_command[@]}" \
            >"${probe_output}" 2>"${probe_error}"; then
            probe_status=0
        else
            probe_status=$?
        fi
        if [[ "${probe_status}" -ne 0 || -s "${probe_error}" ]]; then
            probe_diagnostic="$(
                package_query_diagnostic "${probe_output}" "${probe_error}"
            )"
            panic "${failure_prefix} ${probe_status}; ${probe_diagnostic})"
        fi
        # Keep the raw bytes in files until NUL validation is complete. Bash
        # variables and line reads cannot preserve NUL bytes.
        nul_stripped_output="${probe_output}.without-nul"
        if ! LC_ALL=C tr -d '\000' <"${probe_output}" \
            >"${nul_stripped_output}"; then
            panic "failed to validate Ubuntu package metadata for '${package_name}' (could not inspect apt-cache madison output)"
        fi
        if ! cmp -s -- "${probe_output}" "${nul_stripped_output}"; then
            probe_diagnostic="$(
                package_query_diagnostic "${probe_output}" "${probe_error}"
            )"
            panic "failed to validate Ubuntu package metadata for '${package_name}' (apt-cache madison output was malformed; ${probe_diagnostic})"
        fi
        expected_source="https://${MICROSOFT_PACKAGES_HOST}/ubuntu/${PLATFORM_VERSION}/prod ${ubuntu_suite}/main ${UBUNTU_REPOSITORY_ARCHITECTURE} Packages"
        while IFS= read -r row || [[ -n "${row}" ]]; do
            if [[ -z "${row}" ]]; then
                malformed=true
                break
            fi
            if ! parse_madison_row \
                "${row}" row_package row_version row_source ||
                [[ "${row_package}" != "${package_name}" ]] ||
                ! dpkg --validate-version -- "${row_version}" >/dev/null 2>&1; then
                malformed=true
                break
            fi
            if [[ "${row_source}" == "${expected_source}" ]]; then
                found=true
            fi
        done <"${probe_output}"
        if [[ "${malformed}" == true ]]; then
            probe_diagnostic="$(
                package_query_diagnostic "${probe_output}" "${probe_error}"
            )"
            panic "failed to validate Ubuntu package metadata for '${package_name}' (apt-cache madison output was malformed; ${probe_diagnostic})"
        fi
        [[ "${found}" == true ]]
        return
        ;;
    azurelinux)
        probe_output="${TEMP_DIR}/tdnf-${package_name}.out"
        probe_error="${TEMP_DIR}/tdnf-${package_name}.err"
        clean_status=1
        absence_line="No matching packages to list"
        failure_prefix="failed to query Azure Linux package metadata for '${package_name}' (tdnf status"
        require_command tdnf
        if [[ -n "${azure_repository_id}" ]]; then
            probe_command=(env LC_ALL=C tdnf "--disablerepo=*" \
                "--enablerepo=${azure_repository_id}" list available "${package_name}")
        else
            probe_command=(env LC_ALL=C tdnf list available "${package_name}")
        fi

        # Keep command logging outside captured query output.
        log_command "${probe_command[@]}"
        if "${probe_command[@]}" \
            >"${probe_output}" 2>"${probe_error}"; then
            return 0
        else
            probe_status=$?
        fi
        ;;
    *)
        panic "internal error: package availability has no platform"
        ;;
    esac
    # Azure Linux accepts only its exact native clean-absence response.
    if [[ "${probe_status}" -eq "${clean_status}" ]] &&
        is_clean_package_absence \
            "${probe_output}" "${probe_error}" "${absence_line}"; then
        return 1
    fi
    # Every other nonzero result is an actionable repository query failure.
    probe_diagnostic="$(package_query_diagnostic "${probe_output}" "${probe_error}")"
    panic "${failure_prefix} ${probe_status}; ${probe_diagnostic})"
}

# Checks every package-backed Ubuntu requirement for the currently enabled
# suite, retaining all confirmed absences for one actionable decision.
ubuntu_repository_requirements_available() {
    local suite="$1"
    local kernel_package="${UBUNTU_DRIVER_PACKAGE_FAMILY}-${KERNEL_VERSION}"
    local runtime_package="${API_RUNTIME_PACKAGE}"
    local development_package="${API_DEVELOPMENT_PACKAGES[ubuntu]}"
    local selected_driver=""

    # Each suite probe resets retained requirements and driver selection.
    UBUNTU_MISSING_PACKAGE_REQUIREMENTS=()
    SELECTED_REPOSITORY_DRIVER_PACKAGE=""

    # The installed driver must contain a module for the running kernel.
    if driver_uses_package_repositories; then
        if repository_package_available "${kernel_package}" "${suite}"; then
            selected_driver="${kernel_package}"
        else
            UBUNTU_MISSING_PACKAGE_REQUIREMENTS+=("${kernel_package}")
        fi
    fi

    # Remote API requirements include development content only when requested.
    if api_uses_package_repositories; then
        if ! repository_package_available "${runtime_package}" "${suite}"; then
            UBUNTU_MISSING_PACKAGE_REQUIREMENTS+=("${runtime_package}")
        fi
        if [[ "${API_INSTALL_DEV}" == true ]] &&
            ! repository_package_available "${development_package}" "${suite}"; then
            UBUNTU_MISSING_PACKAGE_REQUIREMENTS+=("${development_package}")
        fi
    fi

    # Driver selection is published only for a complete suite.
    if [[ "${#UBUNTU_MISSING_PACKAGE_REQUIREMENTS[@]}" -ne 0 ]]; then
        return 1
    fi
    SELECTED_REPOSITORY_DRIVER_PACKAGE="${selected_driver}"
}

# Joins requirement labels for concise suite-selection diagnostics.
format_missing_requirements() {
    local requirement=""
    local separator=""
    local rendered=""
    for requirement in "$@"; do
        rendered+="${separator}${requirement}"
        separator=", "
    done
    printf '%s\n' "${rendered}"
}

# Selects stable when complete and falls back to testing only after clean
# package absences. Query and refresh errors remain fatal.
select_ubuntu_repository_suite() {
    local stable_suite=""
    local stable_missing=""
    local testing_missing=""

    # Resolve the stable suite name before querying its package metadata.
    stable_suite="$(ubuntu_stable_repository_suite)"

    # Stable metadata is queried before any testing-suite fallback.
    log_info "Checking Ubuntu stable suite '${stable_suite}' for all required AziHSM packages."
    if ubuntu_repository_requirements_available "${stable_suite}"; then
        SELECTED_UBUNTU_REPOSITORY_SUITE="${stable_suite}"
        log_info "Selected Ubuntu AziHSM repository suite '${stable_suite}'."
        return
    fi
    # Confirmed stable absence triggers one transition to testing.
    stable_missing="$(format_missing_requirements \
        "${UBUNTU_MISSING_PACKAGE_REQUIREMENTS[@]}")"
    log_info "Ubuntu stable suite '${stable_suite}' is missing: ${stable_missing}."
    log_info "Falling back to Ubuntu AziHSM repository suite '${UBUNTU_MICROSOFT_TESTING_SUITE}'."

    # The testing source and cache are activated only after confirmed stable absence.
    configure_ubuntu_repository_suite \
        "${UBUNTU_MICROSOFT_TESTING_SUITE}" \
        "${UBUNTU_REPOSITORY_ARCHITECTURE}"
    refresh_repository_metadata
    log_info "Checking Ubuntu testing suite '${UBUNTU_MICROSOFT_TESTING_SUITE}' for all required AziHSM packages."
    if ubuntu_repository_requirements_available \
        "${UBUNTU_MICROSOFT_TESTING_SUITE}"; then
        SELECTED_UBUNTU_REPOSITORY_SUITE="${UBUNTU_MICROSOFT_TESTING_SUITE}"
        log_info "Selected Ubuntu AziHSM repository suite '${UBUNTU_MICROSOFT_TESTING_SUITE}'."
        return
    fi
    # A second incomplete suite produces one combined actionable failure.
    testing_missing="$(format_missing_requirements \
        "${UBUNTU_MISSING_PACKAGE_REQUIREMENTS[@]}")"
    panic "Ubuntu AziHSM package requirements are unsatisfied: suite '${stable_suite}' missing ${stable_missing}; suite '${UBUNTU_MICROSOFT_TESTING_SUITE}' missing ${testing_missing}"
}

# Installs one selected repository package using explicit native commands.
install_repository_package() {
    local package_name="$1"
    local description="$2"

    # Native package managers install one previously selected package.
    case "${PLATFORM}" in
    ubuntu)
        require_command apt-get
        log_info "Installing Ubuntu ${description} package '${package_name}'."
        if ! execute_command env DEBIAN_FRONTEND=noninteractive \
            apt-get install -y "${package_name}"; then
            panic "failed to install Ubuntu ${description} package '${package_name}'"
        fi
        ;;
    azurelinux)
        require_command tdnf
        log_info "Installing Azure Linux ${description} package '${package_name}'."
        if ! execute_command tdnf install -y "${package_name}"; then
            panic "failed to install Azure Linux ${description} package '${package_name}'"
        fi
        ;;
    *)
        panic "internal error: repository package installation has no platform"
        ;;
    esac
}

# Selects the kernel-specific or fallback driver and installs it.
install_repository_driver() {
    local kernel_package=""
    local fallback_package=""
    local selected_package=""
    local unavailable_message=""

    # Platform policy supplies exact and fallback package identities.
    case "${PLATFORM}" in
    ubuntu)
        if [[ -n "${SELECTED_REPOSITORY_DRIVER_PACKAGE}" ]]; then
            install_repository_package \
                "${SELECTED_REPOSITORY_DRIVER_PACKAGE}" "AziHSM driver"
            return
        fi
        kernel_package="${UBUNTU_DRIVER_PACKAGE_FAMILY}-${KERNEL_VERSION}"
        if [[ "${KERNEL_VERSION}" == *-azure* ]]; then
            fallback_package="${UBUNTU_AZURE_DRIVER_PACKAGE}"
        else
            fallback_package="${UBUNTU_GENERIC_DRIVER_PACKAGE}"
        fi
        unavailable_message="Ubuntu AziHSM packages are unavailable in signed repository metadata; Microsoft repository publication is required"
        # Preserve the pre-query driver prerequisite ordering.
        require_command apt-cache
        require_command apt-get
        ;;
    azurelinux)
        kernel_package="${AZURE_LINUX_DRIVER_PACKAGE_FAMILY}-${KERNEL_VERSION}"
        fallback_package="${AZURE_LINUX_DRIVER_PACKAGE_FAMILY}"
        unavailable_message="Azure Linux AziHSM packages are unavailable in signed repository metadata"
        require_command tdnf
        ;;
    *)
        panic "internal error: repository installation has no platform"
        ;;
    esac
    # Repository metadata determines the narrowest available package.
    if repository_package_available "${kernel_package}"; then
        selected_package="${kernel_package}"
    else
        log_info "Kernel-specific package '${kernel_package}' is unavailable; falling back to '${fallback_package}'."
        if ! repository_package_available "${fallback_package}"; then
            panic "${unavailable_message}"
        fi
        selected_package="${fallback_package}"
    fi
    # Installation occurs only after package selection succeeds.
    install_repository_package "${selected_package}" "AziHSM driver"
}

# Selects local packages or configured repository driver resolution.
install_driver() {
    # Local package overrides bypass repository driver resolution.
    if [[ "${#DRIVER_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        validate_local_packages
        install_local_packages
    else
        install_repository_driver
    fi

    # Package scripts may ignore a failed load, so verify it explicitly.
    require_command modprobe
    if ! execute_command modprobe azihsm; then
        panic "failed to load the AziHSM driver module for running kernel ${KERNEL_VERSION}"
    fi
    log_info "Loaded the AziHSM driver module for running kernel ${KERNEL_VERSION}."
}

# ---------------------------------------------------------------------------
# Resilient API installation
# ---------------------------------------------------------------------------

# Validates one API ELF shared object, host machine, and expected SONAME.
validate_api_shared_object() {
    local library_path="$1"
    local line=""
    local metadata=""
    local machine=""
    local expected_machine=""
    local elf_header_count=0
    local file_marker_count=0
    local machine_count=0
    local machine_match_count=0
    local soname_count=0
    local soname_match_count=0
    local type_count=0
    local type_match_count=0

    # Readelf inspects metadata without loading untrusted input.
    require_command readelf
    if ! metadata="$(env LC_ALL=C readelf -h -d -- "${library_path}")"; then
        panic "failed to inspect local AziHSM API ELF metadata"
    fi
    expected_machine="${ELF_MACHINE_IDENTITIES[${NORMALIZED_ARCHITECTURE}]:-}"
    if [[ -z "${expected_machine}" ]]; then
        panic "cannot validate local AziHSM API ELF machine for unsupported host architecture '${NORMALIZED_ARCHITECTURE}'"
    fi
    # Count the structural markers independently so duplicated or conflicting
    # readelf records cannot satisfy the shared-object contract.
    while IFS= read -r line; do
        if [[ "${line}" =~ ^[[:space:]]*File: ]]; then
            ((file_marker_count += 1))
        elif [[ "${line}" =~ ^ELF[[:space:]]Header:$ ]]; then
            ((elf_header_count += 1))
        elif [[ "${line}" =~ ^[[:space:]]*Type: ]]; then
            ((type_count += 1))
            if [[ "${line}" =~ ^[[:space:]]*Type:[[:space:]]+DYN[[:space:]]\(Shared[[:space:]]object[[:space:]]file\)$ ]]; then
                ((type_match_count += 1))
            fi
        elif [[ "${line}" =~ ^[[:space:]]*Machine: ]]; then
            ((machine_count += 1))
            if [[ "${line}" =~ ^[[:space:]]*Machine:[[:space:]]+([^[:space:]](.*[^[:space:]])?)$ ]]; then
                machine="${BASH_REMATCH[1]}"
                ((machine_match_count += 1))
            fi
        elif [[ "${line}" == *"(SONAME)"* ]]; then
            ((soname_count += 1))
            if [[ "${line}" =~ Library[[:space:]]soname:[[:space:]]\[(.*)\]$ &&
                "${BASH_REMATCH[1]}" == "${API_LIBRARY_SONAME}" ]]; then
                ((soname_match_count += 1))
            fi
        fi
    done <<<"${metadata}"
    # Structural counts enforce one standalone shared object and exact fields.
    if [[ "${file_marker_count}" -ne 0 || "${elf_header_count}" -ne 1 ]]; then
        panic "local AziHSM API library must be one standalone ELF object"
    fi
    if [[ "${type_count}" -ne 1 || "${type_match_count}" -ne 1 ]]; then
        panic "local AziHSM API library must be an ELF shared object"
    fi
    if [[ "${machine_count}" -ne 1 || "${machine_match_count}" -ne 1 ]]; then
        panic "local AziHSM API library must have exactly one valid ELF Machine field"
    fi
    if [[ "${machine}" != "${expected_machine}" ]]; then
        panic "local AziHSM API library ELF machine '${machine}' is incompatible with host architecture '${NORMALIZED_ARCHITECTURE}'"
    fi
    if [[ "${soname_count}" -ne 1 || "${soname_match_count}" -ne 1 ]]; then
        panic "local AziHSM API library must have exact SONAME ${API_LIBRARY_SONAME}"
    fi
}

# Returns success for regular, symlink, or dangling-symlink directory entries.
path_entry_exists() {
    [[ -e "$1" || -L "$1" ]]
}

# Selects distro paths/mode, builds the artifact plan, and validates it.
prepare_local_api_artifact_plan() {
    local library_directory=""
    local destination=""
    local existing_type=""
    local index=0
    API_ARTIFACT_LABELS=()
    API_ARTIFACT_DESTINATIONS=()
    API_ARTIFACT_STAGED_PATHS=()
    API_ARTIFACT_EXISTING_TYPES=()
    API_ARTIFACT_BACKUPS=()
    API_ARTIFACT_PUBLISHED=()

    # Select platform-specific destinations and publication modes.
    case "${PLATFORM}" in
    ubuntu)
        # Keep local Ubuntu runtime and linker artifacts under /usr/lib.
        library_directory="${UBUNTU_API_LIBRARY_DIRECTORY}"
        API_LIBRARY_MODE="0644"
        ;;
    azurelinux)
        # Consume Azure Linux's package-equivalent /usr/lib destination.
        library_directory="${AZURE_LINUX_API_LIBRARY_DIRECTORY}"
        API_LIBRARY_MODE="0755"
        ;;
    *)
        panic "internal error: local API destination mapping has no platform"
        ;;
    esac

    # Build the runtime, optional header, and optional linker artifact plan.
    API_ARTIFACT_LABELS=("runtime")
    API_ARTIFACT_DESTINATIONS=("${library_directory}/${API_LIBRARY_SONAME}")
    API_ARTIFACT_EXISTING_TYPES=("regular file")
    if [[ -n "${API_STAGED_HEADER_PATH}" ]]; then
        API_ARTIFACT_LABELS+=("header")
        API_ARTIFACT_DESTINATIONS+=("${API_INCLUDE_DIRECTORY}/${API_HEADER_NAME}")
        API_ARTIFACT_EXISTING_TYPES+=("regular file")
    fi
    if [[ "${API_INSTALL_DEV}" == true ]]; then
        API_ARTIFACT_LABELS+=("linker symlink")
        API_ARTIFACT_DESTINATIONS+=("${library_directory}/${API_LIBRARY_NAME}")
        API_ARTIFACT_EXISTING_TYPES+=("symlink")
    fi

    # Validate destination types before staging anything for publication.
    for ((index = 0; index < ${#API_ARTIFACT_LABELS[@]}; index++)); do
        destination="${API_ARTIFACT_DESTINATIONS[index]}"
        existing_type="${API_ARTIFACT_EXISTING_TYPES[index]}"
        if [[ ! -d "${destination%/*}" ]]; then
            panic "AziHSM API ${API_ARTIFACT_LABELS[index]} destination directory does not exist: ${destination%/*}"
        fi
        if path_entry_exists "${destination}"; then
            if [[ "${existing_type}" == "regular file" ]]; then
                if [[ ! -f "${destination}" || -L "${destination}" ]]; then
                    panic "existing AziHSM API ${API_ARTIFACT_LABELS[index]} destination is not a regular file: ${destination}"
                fi
            else
                if [[ ! -L "${destination}" ]]; then
                    panic "existing AziHSM API linker destination is not a symlink: ${destination}"
                fi
            fi
        fi
        API_ARTIFACT_STAGED_PATHS+=("")
        API_ARTIFACT_BACKUPS+=("")
        API_ARTIFACT_PUBLISHED+=(false)
    done
}

# Creates and returns private staging on a destination filesystem.
create_api_destination_staging_directory() {
    local destination_directory="$1"
    local output_name="$2"
    local staging_directory=""
    local -n output_ref="${output_name}"
    if ! staging_directory="$(mktemp -d "${destination_directory}/.azihsm-api.XXXXXX")"; then
        panic "failed to create AziHSM API staging directory in ${destination_directory}"
    fi
    API_DESTINATION_STAGING_DIRECTORIES+=("${staging_directory}")
    # shellcheck disable=SC2034  # Nameref output is consumed by the caller.
    output_ref="${staging_directory}"
}

# Restores planned artifacts in reverse publication order and refreshes cache.
rollback_local_api_install() {
    local rollback_failed=false
    local index=0

    # Restore backups or remove newly published artifacts in reverse order.
    for ((index = ${#API_ARTIFACT_LABELS[@]} - 1; index >= 0; index--)); do
        if [[ -n "${API_ARTIFACT_BACKUPS[index]}" ]] &&
            path_entry_exists "${API_ARTIFACT_BACKUPS[index]}"; then
            if mv -fT -- \
                "${API_ARTIFACT_BACKUPS[index]}" \
                "${API_ARTIFACT_DESTINATIONS[index]}"; then
                API_ARTIFACT_BACKUPS[index]=""
                API_ARTIFACT_PUBLISHED[index]=false
            else
                log_error "failed to restore AziHSM API ${API_ARTIFACT_LABELS[index]} from recovery path ${API_ARTIFACT_BACKUPS[index]} to ${API_ARTIFACT_DESTINATIONS[index]}"
                rollback_failed=true
            fi
        elif [[ "${API_ARTIFACT_PUBLISHED[index]}" == true ]]; then
            if rm -f -- "${API_ARTIFACT_DESTINATIONS[index]}"; then
                API_ARTIFACT_PUBLISHED[index]=false
            else
                rollback_failed=true
            fi
        fi
    done
    if ! "${LDCONFIG_PATH}"; then
        rollback_failed=true
    fi
    if [[ "${rollback_failed}" == true ]]; then
        log_error "AziHSM API rollback was incomplete; inspect managed destinations and rerun ${LDCONFIG_PATH}"
        return 1
    fi
    return 0
}

# Rolls back an interrupted API transaction and preserves failed recovery data.
cleanup_local_api_transaction() {
    # Cleanup is a no-op unless publication crossed the transaction boundary.
    if [[ "${API_TRANSACTION_ACTIVE}" != true ]]; then
        return 0
    fi

    # Interrupted publication is rolled back before ordinary workspace removal.
    log_error "local AziHSM API transaction was interrupted; attempting rollback"
    if rollback_local_api_install; then
        API_TRANSACTION_ACTIVE=false
    else
        API_PRESERVE_STAGING=true
        log_error "preserving AziHSM API transaction staging directories for manual recovery: ${API_DESTINATION_STAGING_DIRECTORIES[*]}"
    fi
}

# Atomically publishes staged API artifacts with rollback on any failure.
install_local_api_library() {
    local library_stage_directory=""
    local header_stage_directory=""
    local failure_message=""
    local destination=""
    local stage_directory=""
    local index=0

    # Plan destinations, then stage every artifact on its destination filesystem.
    prepare_local_api_artifact_plan
    if [[ ! -x "${LDCONFIG_PATH}" ]]; then
        panic "required ldconfig executable was not found at ${LDCONFIG_PATH}; install it from trusted base-system media and retry"
    fi
    require_command install
    require_command ln
    require_command mktemp
    require_command mv
    require_command rm
    create_api_destination_staging_directory \
        "${API_ARTIFACT_DESTINATIONS[0]%/*}" library_stage_directory
    API_ARTIFACT_STAGED_PATHS[0]="${library_stage_directory}/${API_LIBRARY_SONAME}"
    if ! install -o root -g root -m "${API_LIBRARY_MODE}" -- \
        "${API_STAGED_LIBRARY_PATH}" "${API_ARTIFACT_STAGED_PATHS[0]}"; then
        panic "failed to stage the local AziHSM API runtime"
    fi
    if [[ -n "${API_STAGED_HEADER_PATH}" ]]; then
        create_api_destination_staging_directory \
            "${API_INCLUDE_DIRECTORY}" header_stage_directory
        API_ARTIFACT_STAGED_PATHS[1]="${header_stage_directory}/${API_HEADER_NAME}"
        if ! install -o root -g root -m 0644 -- \
            "${API_STAGED_HEADER_PATH}" "${API_ARTIFACT_STAGED_PATHS[1]}"; then
            panic "failed to stage the local AziHSM API header"
        fi
    fi
    if [[ "${API_INSTALL_DEV}" == true ]]; then
        index=$((${#API_ARTIFACT_LABELS[@]} - 1))
        API_ARTIFACT_STAGED_PATHS[index]="${library_stage_directory}/${API_LIBRARY_NAME}"
        if ! ln -s -- \
            "${API_LIBRARY_SONAME}" "${API_ARTIFACT_STAGED_PATHS[index]}"; then
            panic "failed to stage the local AziHSM API linker symlink"
        fi
    fi

    # Publish the staged plan atomically while retaining rollback backups.
    API_PRESERVE_STAGING=false
    API_TRANSACTION_ACTIVE=true
    for ((index = 0; index < ${#API_ARTIFACT_LABELS[@]}; index++)); do
        destination="${API_ARTIFACT_DESTINATIONS[index]}"
        stage_directory="${API_ARTIFACT_STAGED_PATHS[index]%/*}"
        if path_entry_exists "${destination}"; then
            API_ARTIFACT_BACKUPS[index]="${stage_directory}/${API_ARTIFACT_LABELS[index]// /-}.backup"
            if ! mv -fT -- \
                "${destination}" "${API_ARTIFACT_BACKUPS[index]}"; then
                failure_message="failed to preserve the existing AziHSM API ${API_ARTIFACT_LABELS[index]}"
                break
            fi
        fi
        API_ARTIFACT_PUBLISHED[index]=true
        if ! mv -fT -- "${API_ARTIFACT_STAGED_PATHS[index]}" "${destination}"; then
            failure_message="failed to atomically install the AziHSM API ${API_ARTIFACT_LABELS[index]}"
            break
        fi
    done

    # Refresh the linker cache only after every artifact is published.
    if [[ -z "${failure_message}" ]]; then
        if ! execute_command "${LDCONFIG_PATH}"; then
            failure_message="ldconfig failed after installing the local AziHSM API"
        fi
    fi

    # Roll back the entire plan if publication or cache refresh failed.
    if [[ -n "${failure_message}" ]]; then
        if ! rollback_local_api_install; then
            API_TRANSACTION_ACTIVE=false
            API_PRESERVE_STAGING=true
            log_error "preserving AziHSM API transaction staging directories for manual recovery: ${API_DESTINATION_STAGING_DIRECTORIES[*]}"
            panic "${failure_message}; rollback also failed"
        fi
        API_TRANSACTION_ACTIVE=false
        panic "${failure_message}; all managed API entries were rolled back"
    fi
    API_TRANSACTION_ACTIVE=false
    for ((index = 0; index < ${#API_ARTIFACT_LABELS[@]}; index++)); do
        log_info "Installed local AziHSM API ${API_ARTIFACT_LABELS[index]}: ${API_ARTIFACT_DESTINATIONS[index]}"
    done
}

# Verifies and installs the mapped API repository package.
install_repository_api_library() {
    local package_name=""

    # Development requests select the platform-specific development package.
    if [[ "${API_INSTALL_DEV}" == true ]]; then
        package_name="${API_DEVELOPMENT_PACKAGES[${PLATFORM}]:-}"
    else
        package_name="${API_RUNTIME_PACKAGE}"
    fi
    # Missing mappings indicate an internal platform definition error.
    if [[ -z "${package_name}" ]]; then
        panic "internal error: API package mapping has no platform"
    fi
    # Platform preconditions require prior suite selection or availability.
    case "${PLATFORM}" in
    ubuntu)
        if [[ -z "${SELECTED_UBUNTU_REPOSITORY_SUITE}" ]]; then
            panic "internal error: Ubuntu repository suite was not selected before API installation"
        fi
        ;;
    azurelinux)
        if ! repository_package_available "${package_name}"; then
            panic "Azure Linux AziHSM API package '${package_name}' is unavailable in signed repository metadata"
        fi
        ;;
    *)
        panic "internal error: API package mapping has no platform"
        ;;
    esac
    # The shared native installer performs the selected package mutation.
    install_repository_package "${package_name}" "AziHSM API"
}

# ---------------------------------------------------------------------------
# KMPP installation
# ---------------------------------------------------------------------------

# Prepares an isolated Ubuntu KMPP source and refreshes only its metadata view.
activate_kmpp_ubuntu_suite() {
    local suite="$1"
    local source_output_name="$2"
    local lists_output_name="$3"
    local staged="${TEMP_DIR}/kmpp-${suite}.list"
    local lists="${TEMP_DIR}/kmpp-${suite}-apt-lists"
    local -n source_output_ref="${source_output_name}"
    local -n lists_output_ref="${lists_output_name}"

    # The managed source limits package selection to the requested KMPP suite.
    {
        printf '%s\n' '# Managed by install-azihsm.sh for KMPP.'
        printf 'deb [arch=%s signed-by=%s] https://%s/ubuntu/%s/prod %s main\n' \
            "${UBUNTU_REPOSITORY_ARCHITECTURE}" \
            "${UBUNTU_MICROSOFT_KEYRING_PATH}" \
            "${MICROSOFT_PACKAGES_HOST}" "${PLATFORM_VERSION}" "${suite}"
    } >"${staged}"

    # APT requires a partial directory beneath each private list workspace.
    if ! mkdir -m 0700 -- "${lists}" "${lists}/partial"; then
        panic "failed to create Ubuntu metadata workspace for KMPP suite '${suite}'"
    fi

    # Probe metadata uses the staged source without publishing host configuration.
    if ! apt-get -o "Dir::Etc::sourcelist=${staged}" \
        -o "Dir::Etc::sourceparts=-" \
        -o "Dir::State::lists=${lists}" update; then
        panic "failed to refresh Ubuntu metadata for KMPP suite '${suite}'"
    fi

    # The caller receives both paths without capturing package-manager output.
    # shellcheck disable=SC2034 # The nameref writes the caller's result variable.
    source_output_ref="${staged}"
    # shellcheck disable=SC2034 # The nameref writes the caller's result variable.
    lists_output_ref="${lists}"
}

# Returns success for the exact AziHSM backend name or a numeric ABI suffix.
is_kmpp_azihsm_backend_filename() {
    local filename="$1"
    local suffix=""

    if [[ "${filename}" == "${KMPP_AZIHSM_BACKEND_BASENAME}" ]]; then
        return
    fi
    if [[ "${filename}" != "${KMPP_AZIHSM_BACKEND_BASENAME}."* ]]; then
        return 1
    fi
    suffix="${filename#"${KMPP_AZIHSM_BACKEND_BASENAME}"}"
    [[ "${suffix}" =~ ^(\.[0-9]+)+$ ]]
}

# Returns success when a package listing contains the AziHSM backend ABI.
package_has_azihsm_backend() {
    local package_listing="$1"
    local entry_path=""
    local line=""
    local -a fields=()

    while IFS= read -r line; do
        if [[ "${line}" == /* ]]; then
            entry_path="${line}"
        else
            read -r -a fields <<<"${line}"
            if [[ "${#fields[@]}" -lt 6 || "${fields[5]}" != ./* ]]; then
                continue
            fi
            entry_path="${fields[5]}"
        fi
        if is_kmpp_azihsm_backend_filename "${entry_path##*/}"; then
            return
        fi
    done <"${package_listing}"
    return 1
}

# Resolves the installed AziHSM backend, preferring the unversioned path.
resolve_kmpp_azihsm_backend_path() {
    local library_directory="$1"
    local exact="${library_directory}/${KMPP_AZIHSM_BACKEND_BASENAME}"
    local candidate=""
    local selected=""
    local LC_ALL=C

    if [[ -f "${exact}" ]]; then
        printf '%s\n' "${exact}"
        return
    fi

    shopt -s nullglob
    for candidate in "${exact}".*; do
        if [[ ! -f "${candidate}" ]]; then
            continue
        fi
        if ! is_kmpp_azihsm_backend_filename "${candidate##*/}"; then
            continue
        fi
        if [[ -z "${selected}" || "${candidate}" < "${selected}" ]]; then
            selected="${candidate}"
        fi
    done
    shopt -u nullglob

    if [[ -z "${selected}" ]]; then
        return 1
    fi
    printf '%s\n' "${selected}"
}

# Downloads one suite's runtime and optional development package for inspection.
probe_kmpp_ubuntu_suite() {
    local suite="$1"
    local prefix="$2"
    local directory="${TEMP_DIR}/kmpp-${suite}-packages"
    local source_path=""
    local lists_path=""
    local package=""
    local runtime=""
    local packages_complete=true
    local has_azihsm_backend=false
    local -a packages=("${UBUNTU_KMPP_RUNTIME_PACKAGE}")
    local -a apt_options=()
    local -a files=()
    local -a runtime_files=()
    local -n files_result="${prefix}_FILES"

    # Development package inspection is enabled only when its installation was requested.
    if [[ "${KMPP_INSTALL_DEV}" == true ]]; then
        packages+=("${UBUNTU_KMPP_DEVELOPMENT_PACKAGE}")
    fi

    # A fresh private directory isolates artifacts from each suite probe.
    rm -rf -- "${directory}"
    if ! mkdir -m 0700 -- "${directory}"; then
        panic "failed to create KMPP download directory"
    fi
    activate_kmpp_ubuntu_suite "${suite}" source_path lists_path
    apt_options=(
        -o "Dir::Etc::sourcelist=${source_path}"
        -o "Dir::Etc::sourceparts=-"
        -o "Dir::State::lists=${lists_path}"
    )

    # Availability establishes whether every requested package is present.
    for package in "${packages[@]}"; do
        if ! repository_package_available \
            "${package}" "${suite}" "${source_path}" "${lists_path}"; then
            packages_complete=false
            break
        fi
        if ! (
            cd -- "${directory}"
            # The root-only inspection workspace intentionally cannot be
            # traversed by _apt. Request the already-required root execution
            # explicitly instead of making apt warn before its root fallback.
            apt-get -o "APT::Sandbox::User=root" \
                "${apt_options[@]}" download "${package}"
        ); then
            panic "failed to download Ubuntu KMPP package '${package}' from '${suite}'"
        fi
    done

    # Runtime contents determine whether the suite supports the AziHSM backend.
    if [[ "${packages_complete}" == true ]]; then
        shopt -s nullglob
        files=("${directory}"/*.deb)
        runtime_files=("${directory}"/libkmpp_*.deb)
        shopt -u nullglob
        if [[ "${#files[@]}" -ne "${#packages[@]}" ||
            "${#runtime_files[@]}" -ne 1 ]]; then
            panic "Ubuntu KMPP suite '${suite}' returned unexpected package files"
        fi
        runtime="${runtime_files[0]}"
        if ! dpkg-deb -c "${runtime}" >"${directory}/runtime.list"; then
            panic "failed to inspect Ubuntu KMPP runtime package from '${suite}'"
        fi
        if package_has_azihsm_backend "${directory}/runtime.list"; then
            has_azihsm_backend=true
        fi
    fi

    # Probe results are returned through caller-selected scalar and array names.
    # shellcheck disable=SC2034 # The nameref writes the caller's result array.
    files_result=("${files[@]}")
    printf -v "${prefix}_PACKAGES_COMPLETE" '%s' "${packages_complete}"
    printf -v "${prefix}_HAS_AZIHSM_BACKEND" '%s' "${has_azihsm_backend}"
}

# Selects the first package-complete Ubuntu suite with the AziHSM backend.
select_kmpp_ubuntu_suite() {
    local stable="" testing="${UBUNTU_MICROSOFT_TESTING_SUITE}"
    local STABLE_PACKAGES_COMPLETE=false STABLE_HAS_AZIHSM_BACKEND=false
    local TESTING_PACKAGES_COMPLETE=false TESTING_HAS_AZIHSM_BACKEND=false
    local -a STABLE_FILES=() TESTING_FILES=()

    # Stable is inspected first and selected only when all packages and the backend exist.
    stable="$(ubuntu_stable_repository_suite)"
    probe_kmpp_ubuntu_suite "${stable}" STABLE

    # Stable results are published only when both probe outcomes are affirmative.
    if [[ "${STABLE_PACKAGES_COMPLETE}" == true &&
        "${STABLE_HAS_AZIHSM_BACKEND}" == true ]]; then
        KMPP_SELECTED_SUITE="${stable}"
        KMPP_PACKAGE_FILES=("${STABLE_FILES[@]}")
        KMPP_INSTALLATION_SUPPORTED=true
        return
    fi

    # Testing is inspected only after stable lacks packages or the backend.
    probe_kmpp_ubuntu_suite "${testing}" TESTING

    # Testing is selected only when all packages and the exact backend exist.
    if [[ "${TESTING_PACKAGES_COMPLETE}" == true &&
        "${TESTING_HAS_AZIHSM_BACKEND}" == true ]]; then
        KMPP_SELECTED_SUITE="${testing}"
        KMPP_PACKAGE_FILES=("${TESTING_FILES[@]}")
        KMPP_INSTALLATION_SUPPORTED=true
        return
    fi

    # Confirmed absence in both suites leaves KMPP entirely unchanged.
    log_info "Warning: no enabled Ubuntu KMPP suite provides a complete AziHSM-capable package set; skipping KMPP."
}

# Selects Azure Linux prod/ms-oss only when its runtime contains the AziHSM backend.
select_kmpp_azurelinux_packages() {
    local repository_id="${AZURE_LINUX_KMPP_REPOSITORY_ID_PREFIX}${NORMALIZED_ARCHITECTURE}"
    local directory="${TEMP_DIR}/kmpp-azurelinux-packages"
    local package=""
    local runtime=""
    local transaction=""
    local -a packages=("${AZURE_LINUX_KMPP_RUNTIME_PACKAGE}")
    local -a files=()
    local -a runtime_files=()
    local -a development_files=()

    # Requested development content must be present with the runtime package.
    if [[ "${KMPP_INSTALL_DEV}" == true ]]; then
        packages+=("${AZURE_LINUX_KMPP_DEVELOPMENT_PACKAGE}")
    fi

    # Confirmed package absence is the only nonfatal repository outcome.
    for package in "${packages[@]}"; do
        if ! repository_package_available "${package}" "${repository_id}"; then
            log_info "Warning: Azure Linux prod/ms-oss lacks the complete AziHSM-capable KMPP package set; skipping KMPP."
            return
        fi
    done

    # Download selected repository artifacts into an isolated inspection directory.
    rm -rf -- "${directory}"
    if ! mkdir -m 0700 -- "${directory}"; then
        panic "failed to create the Azure Linux KMPP download directory"
    fi
    for package in "${packages[@]}"; do
        transaction="install"
        if rpm -q -- "${package}" >/dev/null 2>&1; then
            transaction="reinstall"
        fi
        # Restrict the download-only transaction to the same prod/ms-oss
        # repository used by the availability check, including dependencies.
        if ! tdnf "--disablerepo=*" "--enablerepo=${repository_id}" --downloadonly \
            "--downloaddir=${directory}" "${transaction}" -y \
            "${package}"; then
            panic "failed to download Azure Linux KMPP package '${package}' from prod/ms-oss"
        fi
    done

    # Select only requested KMPP artifacts; tdnf may also download missing dependencies.
    shopt -s nullglob
    runtime_files=("${directory}"/kmpp-[0-9]*.rpm)
    if [[ "${KMPP_INSTALL_DEV}" == true ]]; then
        development_files=("${directory}"/kmpp-devel-[0-9]*.rpm)
    fi
    shopt -u nullglob
    if [[ "${#runtime_files[@]}" -ne 1 ||
        "${KMPP_INSTALL_DEV}" == true && "${#development_files[@]}" -ne 1 ]]; then
        panic "Azure Linux prod/ms-oss returned unexpected KMPP package files"
    fi
    files=("${runtime_files[@]}" "${development_files[@]}")
    runtime="${runtime_files[0]}"

    # Runtime payload inspection gates all KMPP host mutation.
    if ! rpm -qlp -- "${runtime}" >"${directory}/runtime.list"; then
        panic "failed to inspect the Azure Linux KMPP runtime package from prod/ms-oss"
    fi
    if ! package_has_azihsm_backend "${directory}/runtime.list"; then
        log_info "Warning: Azure Linux prod/ms-oss KMPP lacks ${KMPP_AZIHSM_BACKEND_BASENAME}; skipping KMPP."
        return
    fi

    # Publish the Azure Linux package plan only after backend payload inspection.
    KMPP_PACKAGE_FILES=("${files[@]}")
    KMPP_INSTALLATION_SUPPORTED=true
}

# Stages the exact KMPP runtime configuration in the protected workspace.
stage_managed_kmpp_runtime_config() {
    local staged="${TEMP_DIR}/kmpp-config.cnf"

    # Staging keeps the canonical bytes ready until package installation succeeds.
    if ! printf '[ kmpp_config ]\nkeyiso_solution_type = azihsm\n\n[ enable_by_default ]\nactive = 0\n' \
        >"${staged}"; then
        panic "failed to stage the KMPP AziHSM configuration"
    fi
}

# Selects an AziHSM-capable package set and validates host compatibility.
prepare_kmpp_packages() {
    local command_name=""
    local config_directory="" config_path="" status=0
    local -a commands=(grep install openssl)

    # Platform-specific package tools are required before repository inspection.
    if [[ "${#KMPP_PACKAGE_PATHS[@]}" -eq 0 && "${PLATFORM}" == ubuntu ]]; then
        commands+=(apt-get dpkg-deb)
    fi
    if [[ "${#KMPP_PACKAGE_PATHS[@]}" -eq 0 && "${PLATFORM}" == azurelinux ]]; then
        commands+=(rpm tdnf)
    fi

    # Every selection and compatibility command is required before inspection.
    for command_name in "${commands[@]}"; do
        require_command "${command_name}"
    done

    # Local overrides bypass repository selection; readiness is checked after install.
    KMPP_INSTALLATION_SUPPORTED=false
    KMPP_PACKAGE_FILES=()
    if [[ "${#KMPP_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        KMPP_PACKAGE_FILES=("${KMPP_PACKAGE_PATHS[@]}")
        KMPP_INSTALLATION_SUPPORTED=true
        get_temporary_workspace
    elif [[ "${PLATFORM}" == ubuntu ]]; then
        select_kmpp_ubuntu_suite
    else
        select_kmpp_azurelinux_packages
    fi
    if [[ "${KMPP_INSTALLATION_SUPPORTED}" == false ]]; then
        return
    fi

    # Canonical configuration is staged without changing the target filesystem.
    stage_managed_kmpp_runtime_config

    # Existing global provider wiring must be resolved outside this installer.
    if ! config_directory="$(openssl info -configdir)"; then
        panic "failed to locate the OpenSSL configuration directory"
    fi
    config_path="${config_directory}/openssl.cnf"
    if [[ ! -r "${config_path}" ]]; then
        panic "cannot read ${config_path}"
    fi
    if grep -Eiq '^[[:space:]]*[^#;].*(kmpp(_dflt)?_prov\.cnf|kmppprovider(_dflt)?)' \
        "${config_path}"; then
        status=0
    else
        status=$?
    fi
    case "${status}" in
    0)
        panic "global KMPP OpenSSL wiring exists in ${config_path}; remove it before installing"
        ;;
    1)
        ;;
    *)
        panic "failed to inspect ${config_path}"
        ;;
    esac

    # The selected suite is reported only when installation will proceed.
    if [[ "${#KMPP_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        log_info "Selected local KMPP package(s): ${#KMPP_PACKAGE_FILES[@]}."
    elif [[ "${PLATFORM}" == ubuntu ]]; then
        log_info "Selected AziHSM-capable Ubuntu KMPP suite '${KMPP_SELECTED_SUITE}'."
    else
        log_info "Selected AziHSM-capable Azure Linux KMPP packages from prod/ms-oss."
    fi
}

# Installs a prevalidated package set and verifies AziHSM readiness.
install_kmpp() {
    local library_directory="${KMPP_FILESYSTEM_ROOT}/usr/lib64" output=""
    local staged="${TEMP_DIR}/kmpp-config.cnf"

    # The opt-out marker keeps KMPP from changing the host-wide OpenSSL provider.
    if ! install -d -o root -g root -m 0755 -- \
        "${KMPP_OPENSSL_MARKER_PATH%/*}"; then
        panic "failed to create ${KMPP_OPENSSL_MARKER_PATH%/*}"
    fi

    # Existing markers are retained while absent markers are created securely.
    if [[ ! -e "${KMPP_OPENSSL_MARKER_PATH}" ]]; then
        if ! install -o root -g root -m 0644 -- \
            /dev/null "${KMPP_OPENSSL_MARKER_PATH}"; then
            panic "failed to create ${KMPP_OPENSSL_MARKER_PATH}"
        fi
    fi

    # Marker permissions are normalized on new and repeated installations.
    if ! chmod 0644 -- "${KMPP_OPENSSL_MARKER_PATH}"; then
        panic "failed to secure ${KMPP_OPENSSL_MARKER_PATH}"
    fi

    # Each platform installs only from the package artifacts selected during preflight.
    if [[ "${#KMPP_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        install_local_packages KMPP_PACKAGE_FILES KMPP
    fi
    if [[ "${PLATFORM}" == ubuntu ]]; then
        if [[ "${#KMPP_PACKAGE_PATHS[@]}" -eq 0 ]] && ! DEBIAN_FRONTEND=noninteractive \
            apt-get install -y -- "${KMPP_PACKAGE_FILES[@]}"; then
            panic "failed to install Ubuntu KMPP packages from '${KMPP_SELECTED_SUITE}'"
        fi
        library_directory="${KMPP_FILESYSTEM_ROOT}/usr/lib/x86_64-linux-gnu"
        KMPP_PROVIDER_PATH="${library_directory}/ossl-modules/kmppprovider.so"
    else
        if [[ "${#KMPP_PACKAGE_PATHS[@]}" -eq 0 ]] && ! tdnf --noautoremove install -y "${KMPP_PACKAGE_FILES[@]}"; then
            panic "failed to install Azure Linux KMPP packages from prod/ms-oss"
        fi
        KMPP_PROVIDER_PATH="${KMPP_FILESYSTEM_ROOT}/usr/lib/ossl-modules/kmppprovider.so"
    fi

    # Publish canonical AziHSM settings only after package installation succeeds.
    log_info "Creating/configuring KMPP to use AziHSM with secure modes; default activation remains disabled. KMPP may change ownership to kmpp:kmpp when its service starts."
    if ! execute_command install -d -o root -g root -m 0755 -- \
        "${KMPP_RUNTIME_CONFIG_PATH%/*}"; then
        panic "failed to create the KMPP AziHSM configuration directory"
    fi
    if ! execute_command install -o root -g root -m 0644 -- "${staged}" \
        "${KMPP_RUNTIME_CONFIG_PATH}"; then
        panic "failed to install the KMPP AziHSM configuration"
    fi

    # Provider, runtime, and AziHSM backend artifacts are mandatory after installation.
    if [[ ! -f "${KMPP_PROVIDER_PATH}" ||
        ! -f "${library_directory}/libkmpp.so.1" ]]; then
        panic "KMPP installation is missing the provider or runtime library"
    fi
    if ! KMPP_AZIHSM_BACKEND_PATH="$(
        resolve_kmpp_azihsm_backend_path "${library_directory}"
    )"; then
        panic "KMPP installation is missing the provider or runtime library"
    fi
    if [[ ! -f "${KMPP_AZIHSM_BACKEND_PATH}" ]]; then
        panic "KMPP installation is missing the provider or runtime library"
    fi

    # An explicit provider load validates KMPP without modifying global OpenSSL state.
    if ! output="$(OPENSSL_CONF=/dev/null openssl list -providers \
        -provider-path "${KMPP_PROVIDER_PATH%/*}" \
        -provider default -provider "${KMPP_PROVIDER_NAME}")"; then
        panic "explicit KMPP provider loading failed"
    fi
    if ! grep -Fq "${KMPP_PROVIDER_NAME}" <<<"${output}"; then
        panic "explicit provider output did not identify ${KMPP_PROVIDER_NAME}"
    fi

    # Service activation is deferred when systemd is unavailable, such as in image builds.
    if [[ ! -d "${KMPP_SYSTEMD_RUNTIME_DIRECTORY}" ]] ||
        ! command -v systemctl >/dev/null 2>&1 ||
        ! systemctl show --property=Version --value >/dev/null 2>&1; then
        KMPP_SERVICE_READINESS_DEFERRED=true
    else
        # Check if the KMPP service is up and running.
        if ! execute_command systemctl is-active --quiet "${KMPP_MAIN_UNIT}"; then
            # Rebuild systemd's internal tree of services, to be sure that the KMPP
            # service is properly identified in our next command.
            if ! execute_command systemctl daemon-reload; then
                panic "KMPP main service failed to reach active state"
            fi
            if ! execute_command systemctl is-active --quiet "${KMPP_MAIN_UNIT}"; then
                panic "KMPP main service failed to reach active state"
            fi
        fi
        KMPP_SERVICE_READINESS_DEFERRED=false
    fi

    # Readiness reports only the supported AziHSM configuration.
    output="KMPP_AZIHSM_COMPONENTS_INSTALLED"
    if [[ "${KMPP_SERVICE_READINESS_DEFERRED}" == true ]]; then
        output+="; SERVICE_READINESS_DEFERRED"
    fi

    # The final status summarizes provider and optional service readiness.
    log_info "KMPP readiness: ${output}."
}

# ---------------------------------------------------------------------------
# User group setup
# ---------------------------------------------------------------------------

# Returns success for conservative, unambiguous local Linux account names.
is_valid_user_group_username() {
    local username="$1"
    [[ "${#username}" -le 32 &&
        "${username}" =~ ^[a-z_][a-z0-9_.-]*\$?$ ]]
}

# Adds one username to the target list unless an earlier source selected it.
add_user_group_target() {
    local username="$1"
    local existing_username=""

    # First occurrence wins across sudo-invoker and explicit-list sources.
    for existing_username in "${USER_GROUP_TARGETS[@]}"; do
        if [[ "${existing_username}" == "${username}" ]]; then
            return
        fi
    done
    # A new validated account is appended in source order.
    USER_GROUP_TARGETS+=("${username}")
}

# Validates and selects the sudo invoker followed by explicit users.
select_user_group_targets() {
    local sudo_user="${SUDO_USER:-}"
    local username=""
    local -a explicit_users=()

    # Selection is rebuilt from trusted validation results on each invocation.
    USER_GROUP_TARGETS=()

    # A valid non-root sudo invoker is the first implicit target.
    if [[ -n "${sudo_user}" && "${sudo_user}" != "root" ]]; then
        if ! is_valid_user_group_username "${sudo_user}"; then
            panic "SUDO_USER contains an invalid username; clear the untrusted SUDO_USER environment value or use --skip-user-groups"
        fi
        add_user_group_target "${sudo_user}"
    fi

    # Explicit comma-separated targets reject empty, invalid, and root entries.
    if [[ "${USER_GROUPS_ADD_LIST_PROVIDED}" == true ]]; then
        if [[ "${USER_GROUPS_ADD_LIST}" == ,* ||
            "${USER_GROUPS_ADD_LIST}" == *, ||
            "${USER_GROUPS_ADD_LIST}" == *,,* ]]; then
            panic "--user-groups-add-list contains an empty username"
        fi
        IFS=',' read -r -a explicit_users <<<"${USER_GROUPS_ADD_LIST}"
        for username in "${explicit_users[@]}"; do
            if ! is_valid_user_group_username "${username}"; then
                panic "--user-groups-add-list contains an invalid username: '${username}'"
            fi
            if [[ "${username}" == "root" ]]; then
                panic "--user-groups-add-list must not include root"
            fi
            add_user_group_target "${username}"
        done
    fi

    # Group setup requires at least one non-root account.
    if [[ "${#USER_GROUP_TARGETS[@]}" -eq 0 ]]; then
        panic "no non-root sudo invoker was found; specify --user-groups-add-list USERNAME[,USERNAME...] or use --skip-user-groups"
    fi
}

# Inventories missing groups while distinguishing absence from lookup failure.
find_missing_device_access_groups() {
    local group_name=""
    local lookup_status=0

    # Missing-group inventory is rebuilt from native account database results.
    MISSING_DEVICE_ACCESS_GROUPS=()

    # Each lookup distinguishes a missing group from account-database failure.
    for group_name in "${DEVICE_ACCESS_GROUPS[@]}"; do
        if getent group -- "${group_name}" >/dev/null; then
            continue
        else
            lookup_status=$?
        fi
        if [[ "${lookup_status}" -eq 2 ]]; then
            MISSING_DEVICE_ACCESS_GROUPS+=("${group_name}")
        else
            panic "failed to look up required group '${group_name}' with getent"
        fi
    done
}

# Preflights commands, accounts, groups, and membership reads before mutation.
prepare_user_group_setup() {
    local username=""
    local group_name=""
    local command_name=""
    local group_memberships=""
    local membership=""
    local additions=""
    local has_membership=false
    local -a current_memberships=()

    # All commands and account targets are validated before host mutation.
    for command_name in getent groupadd id usermod; do
        require_command "${command_name}"
    done
    select_user_group_targets

    # Every target account must resolve before group creation or membership edits.
    for username in "${USER_GROUP_TARGETS[@]}"; do
        if ! getent passwd -- "${username}" >/dev/null; then
            panic "user account '${username}' was not found; create the account or remove it from --user-groups-add-list"
        fi
    done

    # Required group absence is inventoried before membership planning.
    find_missing_device_access_groups

    # Per-user additions retain current supplementary memberships.
    USER_GROUP_MEMBERSHIP_ADDITIONS=()
    for username in "${USER_GROUP_TARGETS[@]}"; do
        if ! group_memberships="$(id -nG -- "${username}")"; then
            panic "failed to read current group memberships for user '${username}'"
        fi
        read -r -a current_memberships <<<"${group_memberships}"
        additions=""
        for group_name in "${DEVICE_ACCESS_GROUPS[@]}"; do
            has_membership=false
            for membership in "${current_memberships[@]}"; do
                if [[ "${membership}" == "${group_name}" ]]; then
                    has_membership=true
                    break
                fi
            done
            if [[ "${has_membership}" == true ]]; then
                continue
            fi
            if [[ -n "${additions}" ]]; then
                additions+=","
            fi
            additions+="${group_name}"
        done
        USER_GROUP_MEMBERSHIP_ADDITIONS+=("${additions}")
    done
}

# Creates missing system groups and applies the preflighted additive memberships.
setup_user_groups() {
    local group_name=""
    local username=""
    local additions=""
    local index=0
    local changed=false

    # Driver packages may create these groups after the initial preflight.
    find_missing_device_access_groups
    for group_name in "${MISSING_DEVICE_ACCESS_GROUPS[@]}"; do
        log_info "Creating system group '${group_name}'."
        if ! execute_command groupadd --system -- "${group_name}"; then
            panic "failed to create required system group '${group_name}'"
        fi
    done

    # Planned additive memberships are applied without replacing other groups.
    for ((index = 0; index < ${#USER_GROUP_TARGETS[@]}; index++)); do
        username="${USER_GROUP_TARGETS[index]}"
        additions="${USER_GROUP_MEMBERSHIP_ADDITIONS[index]}"
        if [[ -z "${additions}" ]]; then
            log_info "User '${username}' already belongs to both required device access groups."
            continue
        fi
        log_info "Adding user '${username}' to device access group(s): ${additions}."
        if ! execute_command usermod --append --groups "${additions}" "${username}"; then
            panic "failed to add user '${username}' to required device access group(s): ${additions}"
        fi
        changed=true
    done

    # Completion output distinguishes changed sessions from idempotent runs.
    if [[ "${changed}" == true ]]; then
        log_info "User group changes take effect after affected users re-login or refresh their sessions."
    else
        log_info "All selected users already have the required AziHSM and TPM group access."
    fi
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

# Runs the installation steps in their required order.
main() {
    parse_arguments "$@"
    require_root

    # Reject contradictory options before detecting or changing host state.
    if [[ "${SKIP_DRIVER}" == true && "${#DRIVER_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        panic "--driver-path cannot be used with --skip-driver"
    fi
    if [[ "${SKIP_API}" == true && "${#API_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        panic "--api-path cannot be used with --skip-api"
    fi
    if [[ "${SKIP_API}" == true && "${API_INSTALL_DEV}" == true ]]; then
        panic "--api-install-dev cannot be used with --skip-api"
    fi
    if [[ "${SKIP_KMPP}" == true && "${KMPP_INSTALL_DEV}" == true ]]; then
        panic "--kmpp-install-dev cannot be used with --skip-kmpp"
    fi
    if [[ "${SKIP_KMPP}" == true && "${#KMPP_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        panic "--kmpp-path cannot be used with --skip-kmpp"
    fi
    if [[ "${SKIP_USER_GROUPS}" == false ]]; then
        prepare_user_group_setup
    fi

    # Detect all machine facts before prerequisite and repository selection;
    # `PLATFORM`, `PLATFORM_VERSION`, `KERNEL_VERSION`, and
    # `NORMALIZED_ARCHITECTURE` feed every later platform-specific stage.
    print_section_header "Environment Detection"
    detect_supported_architecture
    detect_kernel
    detect_platform
    echo ""

    # Repository-backed runs validate bootstrap tools, configure trusted
    # sources, and refresh the shared package cache before any package action.
    print_section_header "Repository & Dependency Configuration"
    if repositories_needed; then
        validate_repository_bootstrap_prerequisites
        configure_repositories
        refresh_repository_metadata
        if [[ "${PLATFORM}" == "ubuntu" ]]; then
            select_ubuntu_repository_suite
        fi
        install_runtime_prerequisites true
    else
        # Local packages may use native repositories for validation tools;
        # local and disabled package flows never consume PMC packages.
        install_runtime_prerequisites false
    fi
    echo ""

    # Validate every local package before driver or other component mutation.
    validate_local_packages
    if [[ "${SKIP_API}" == false && "${#API_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        validate_local_packages API_PACKAGE_PATHS "local AziHSM API package"
    fi
    validate_local_packages KMPP_PACKAGE_PATHS "local KMPP package"
    if [[ "${SKIP_KMPP}" == false ]]; then
        prepare_kmpp_packages
    fi

    # Install the AziHSM driver, either from a local package (provided by the
    # user) or from the configured remote repositories.
    print_section_header "AziHSM Driver Install"
    if [[ "${SKIP_DRIVER}" == true ]]; then
        log_info "Skipping AziHSM driver installation."
    else
        install_driver
    fi
    echo ""

    # Create the required device groups and add every preflighted target user
    # without replacing any existing supplementary memberships.
    print_section_header "AziHSM User Group Setup"
    if [[ "${SKIP_USER_GROUPS}" == true ]]; then
        log_info "Skipping all user discovery and azihsm/tss group setup."
    else
        setup_user_groups
    fi
    echo ""

    # Install the AziHSM API library onto the system.
    print_section_header "AziHSM API Install"
    if [[ "${SKIP_API}" == true ]]; then
        log_info "Skipping AziHSM API installation."
    elif [[ "${#API_PACKAGE_PATHS[@]}" -gt 0 ]]; then
        install_local_packages API_PACKAGE_PATHS "AziHSM API"
    else
        install_repository_api_library
    fi
    echo ""

    # KMPP installs the selected package set and verifies AziHSM readiness.
    print_section_header "KMPP Install"
    if [[ "${SKIP_KMPP}" == true ]]; then
        log_info "Skipping KMPP installation and readiness validation."
    elif [[ "${KMPP_INSTALLATION_SUPPORTED}" == false ]]; then
        log_info "KMPP installation was skipped because no selected package set contains the AziHSM backend."
    else
        install_kmpp
    fi
    echo ""

    # Successful completion means every enabled component stage finished.
    log_info "AziHSM installation steps completed."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
