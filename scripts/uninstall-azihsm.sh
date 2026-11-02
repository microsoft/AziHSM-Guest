#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Removes AziHSM Linux driver and resilient API components while retaining
# Microsoft repositories and separately managed KMPP state.

set -euo pipefail

readonly PROGRAM_NAME="${0##*/}"
readonly DEFAULT_OS_RELEASE_FILE="/etc/os-release"

# Keep these platform and architecture constants aligned with install-azihsm.sh.
readonly -a SUPPORTED_UBUNTU_VERSIONS=("22.04" "24.04")
readonly -a SUPPORTED_AZURE_LINUX_VERSIONS=("3" "3.*")
readonly -a SUPPORTED_ARCHITECTURE_NAMES=("x86_64" "amd64")
declare -Ar ARCHITECTURE_ALIASES=(
    [x86_64]="x86_64"
    [amd64]="x86_64"
)

# Keep the API artifact names aligned with the installer.
readonly API_LIBRARY_NAME="libazihsm_api_resilient.so"
readonly API_LIBRARY_SONAME="libazihsm_api_resilient.so.1"
readonly API_HEADER_NAME="azihsm_api_resilient.h"

# Package identities stay aligned with the installer and drive all inventory
# matching and native package-manager removal plans.
readonly UBUNTU_DRIVER_PACKAGE_FAMILY="azihsm-module"
readonly AZURE_LINUX_DRIVER_PACKAGE_FAMILY="azihsm-driver"
readonly API_RUNTIME_PACKAGE="libazihsmr"
declare -Ar API_DEVELOPMENT_PACKAGES=(
    [ubuntu]="${API_RUNTIME_PACKAGE}-dev"
    [azurelinux]="${API_RUNTIME_PACKAGE}-devel"
)

# Exact fixed candidate directories cover Azure Linux, Ubuntu multiarch, and
# conventional local installations without traversing whole directory trees.
readonly -a API_LIBRARY_DIRECTORIES=(
    "/usr/lib"
    "/usr/lib/x86_64-linux-gnu"
    "/usr/lib64"
    "/usr/local/lib"
)
readonly -a API_HEADER_DIRECTORIES=("/usr/include" "/usr/local/include")
readonly LDCONFIG="/sbin/ldconfig"
readonly OS_RELEASE_FILE="${AZIHSM_OS_RELEASE_FILE:-${DEFAULT_OS_RELEASE_FILE}}"

# Fixed system paths have narrow environment overrides solely for isolated tests.
readonly SYS_MODULE_ROOT_DEFAULT="${AZIHSM_SYS_MODULE_ROOT:-/sys/module}"
readonly MODPROBE_PATH_DEFAULT="${AZIHSM_MODPROBE_PATH:-/sbin/modprobe}"
readonly MODULE_NAME="azihsm"

SKIP_DRIVER=false
SKIP_API=false
SYS_MODULE_ROOT=""
MODPROBE_PATH=""
PLATFORM=""
PLATFORM_VERSION=""
NORMALIZED_ARCHITECTURE=""
LOCAL_TRANSACTION_ACTIVE=false
LOCAL_TRANSACTION_LIBRARY_CHANGED=false
declare -a INSTALLED_PACKAGE_NAMES=()
declare -a DRIVER_PACKAGE_PLAN=()
declare -a API_PACKAGE_PLAN=()
declare -a API_PACKAGE_PLANNED_PATHS=()
declare -a LOCAL_PATH_KINDS=()
declare -a LOCAL_PATH_DESTINATIONS=()
declare -a LOCAL_PATH_BACKUPS=()
declare -a LOCAL_PATH_MOVED=()
LOCAL_PLAN_REQUIRES_LDCONFIG=false

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

# Renders and logs exact argument boundaries without evaluating shell text.
log_command() {
    local argument=""
    local quoted=""
    local rendered=""
    for argument in "$@"; do
        printf -v quoted '%q' "${argument}"
        [[ -z "${rendered}" ]] || rendered+=" "
        rendered+="${quoted}"
    done
    log_info "Command: ${rendered}"
}

# Logs and executes one command without reinterpreting its argument array.
execute_command() {
    log_command "$@"
    "$@"
}

# Shows standalone uninstaller behavior and supported options.
usage() {
    cat <<EOF
Usage: ${PROGRAM_NAME} [OPTIONS]

Remove the AziHSM Linux driver and resilient API.

KMPP is managed separately, and this script leaves all KMPP state untouched.
See https://github.com/microsoft/KMPP for KMPP management and uninstall guidance.

This script must be run as root (EUID 0). It never invokes sudo.
Local API cleanup checks fixed exact candidates under
(${API_LIBRARY_DIRECTORIES[*]} and ${API_HEADER_DIRECTORIES[*]}); candidate
directories are not configurable.

Options:
  --skip-driver   Skip module and driver package removal.
  --skip-api      Skip API package and local file removal.
  -h, --help      Show this help and exit.
EOF
}

# Parses only the documented options and rejects missing or positional values.
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        --skip-driver)
            SKIP_DRIVER=true
            shift
            ;;
        --skip-api)
            SKIP_API=true
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            [[ $# -eq 0 ]] || panic "positional arguments are not supported"
            return
            ;;
        -*)
            panic "unknown option: $1 (try --help)"
            ;;
        *)
            panic "unexpected positional argument '$1'"
            ;;
        esac
    done
}

# Returns success when the effective user ID is zero; tests may override it.
is_running_as_root() {
    [[ "${EUID}" -eq 0 ]]
}

# Enforces the standalone root gate before host inspection or mutation.
require_root() {
    if ! is_running_as_root; then
        panic "this uninstaller must be run as root (EUID 0); rerun it from a root shell"
    fi
}

# Removes matching outer quotes from an os-release value.
strip_outer_quotes() {
    local value="$1"
    if [[ "${#value}" -ge 2 ]] &&
        { [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] ||
          [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; }; then
        value="${value:1:${#value}-2}"
    fi
    printf '%s\n' "${value}"
}

# Matches exact versions and the canonical trailing-wildcard Azure entry.
is_supported_version() {
    local version="$1"
    shift
    local supported=""
    for supported in "$@"; do
        if [[ "${supported}" == *"*" &&
            "${version}" == "${supported%\*}"* ]]; then
            return 0
        fi
        [[ "${version}" == "${supported}" ]] && return 0
    done
    return 1
}

# Requires a named command to resolve before any enabled stage mutates state.
require_command() {
    local command_name="$1"
    command -v "${command_name}" >/dev/null 2>&1 ||
        panic "required command '${command_name}' was not found on PATH"
}

# Canonicalizes an absolute existing directory and rejects control characters.
canonicalize_directory() {
    local input="$1"
    local description="$2"
    local output_name="$3"
    local resolved=""
    local -n output_ref="${output_name}"
    [[ "${input}" =~ ^/[A-Za-z0-9_+./-]+$ ]] ||
        panic "${description} must be an absolute path containing only safe path characters"
    [[ -d "${input}" && ! -L "${input}" ]] ||
        panic "${description} is not an existing non-symlink directory: ${input}"
    resolved="$(realpath -e -- "${input}")" ||
        panic "failed to resolve ${description}: ${input}"
    [[ -d "${resolved}" && ! -L "${resolved}" ]] ||
        panic "${description} did not resolve to a non-symlink directory: ${input}"
    output_ref="${resolved}"
}

# Canonicalizes an absolute executable path for fixed privileged invocation.
canonicalize_executable() {
    local input="$1"
    local description="$2"
    local output_name="$3"
    local resolved=""
    local -n output_ref="${output_name}"
    [[ "${input}" =~ ^/[A-Za-z0-9_+./-]+$ ]] ||
        panic "${description} must be an absolute path containing only safe path characters"
    [[ -f "${input}" && -x "${input}" ]] ||
        panic "${description} is not an executable regular file: ${input}"
    resolved="$(realpath -e -- "${input}")" ||
        panic "failed to resolve ${description}: ${input}"
    [[ -f "${resolved}" && -x "${resolved}" ]] ||
        panic "${description} did not resolve to an executable regular file: ${input}"
    # Invoke the validated configured path itself so logs match administrator
    # intent while the resolved target above proves it is a usable executable.
    output_ref="${input}"
}

# Detects and validates the canonical supported machine architecture set.
detect_supported_architecture() {
    local reported=""
    local key=""
    require_command uname
    reported="$(uname -m)" || panic "failed to detect the machine architecture"
    key="${reported,,}"
    case "${key}" in
    x86_64 | amd64)
        NORMALIZED_ARCHITECTURE="${ARCHITECTURE_ALIASES[${key}]}"
        ;;
    *)
        panic "unsupported architecture '${reported}'; supported values are ${SUPPORTED_ARCHITECTURE_NAMES[*]}"
        ;;
    esac
    log_info "Detected machine architecture: '${reported}', normalized to '${NORMALIZED_ARCHITECTURE}'."
}

# Detects only supported Ubuntu and Azure Linux releases.
detect_platform() {
    local line=""
    local key=""
    local value=""
    local os_id=""
    local version_id=""
    [[ -r "${OS_RELEASE_FILE}" ]] ||
        panic "cannot read OS release information from ${OS_RELEASE_FILE}"
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        [[ "${line}" == *=* ]] || continue
        key="${line%%=*}"
        value="$(strip_outer_quotes "${line#*=}")"
        case "${key}" in
        ID) os_id="${value,,}" ;;
        VERSION_ID) version_id="${value}" ;;
        esac
    done <"${OS_RELEASE_FILE}"
    [[ -n "${os_id}" ]] || panic "${OS_RELEASE_FILE} does not define ID"
    [[ -n "${version_id}" ]] || panic "${OS_RELEASE_FILE} does not define VERSION_ID"
    case "${os_id}" in
    ubuntu)
        is_supported_version "${version_id}" "${SUPPORTED_UBUNTU_VERSIONS[@]}" ||
            panic "unsupported Ubuntu version '${version_id}'; supported versions are 22.04 and 24.04"
        PLATFORM="ubuntu"
        ;;
    azurelinux)
        is_supported_version "${version_id}" "${SUPPORTED_AZURE_LINUX_VERSIONS[@]}" ||
            panic "unsupported Azure Linux version '${version_id}'; supported version is 3"
        PLATFORM="azurelinux"
        ;;
    *)
        panic "unsupported Linux distribution '${os_id}' (VERSION_ID='${version_id}')"
        ;;
    esac
    PLATFORM_VERSION="${version_id}"
    log_info "Detected ${os_id} ${PLATFORM_VERSION}."
}

# Resolves the sys module root before any package or module action.
validate_paths() {
    if [[ "${SKIP_DRIVER}" == true && "${SKIP_API}" == true ]]; then
        return
    fi
    if [[ "${SKIP_DRIVER}" == false || "${SKIP_API}" == false ]]; then
        require_command realpath
    fi
    if [[ "${SKIP_DRIVER}" == false ]]; then
        canonicalize_directory "${SYS_MODULE_ROOT_DEFAULT}" "sys module root" SYS_MODULE_ROOT
    fi
}

# Preflights every command needed by enabled stages before the module unload.
validate_prerequisites() {
    if [[ "${SKIP_DRIVER}" == false ]] &&
        path_entry_exists "${SYS_MODULE_ROOT}/${MODULE_NAME}"; then
        canonicalize_executable "${MODPROBE_PATH_DEFAULT}" "modprobe path" MODPROBE_PATH
    fi
    if [[ "${PLATFORM}" == "ubuntu" ]]; then
        require_command dpkg-query
        if [[ "${SKIP_DRIVER}" == false || "${SKIP_API}" == false ]]; then
            require_command apt-get
        fi
    else
        require_command rpm
        if [[ "${SKIP_DRIVER}" == false || "${SKIP_API}" == false ]]; then
            require_command tdnf
        fi
    fi
    if [[ "${SKIP_API}" == false ]]; then
        require_command mv
        require_command rm
        require_command readlink
    fi
}

# Inventories the complete installed package database once and validates output.
inventory_installed_packages() {
    local output=""
    local line=""
    local package=""
    local status=""
    INSTALLED_PACKAGE_NAMES=()
    if [[ "${PLATFORM}" == "ubuntu" ]]; then
        if ! output="$(LC_ALL=C dpkg-query -W -f='${Package}\t${Status}\n')"; then
            panic "failed to enumerate the installed Ubuntu package database"
        fi
        while IFS= read -r line || [[ -n "${line}" ]]; do
            [[ -n "${line}" ]] || continue
            [[ "${line}" == *$'\t'* ]] ||
                panic "malformed output from dpkg-query package enumeration"
            package="${line%%$'\t'*}"
            status="${line#*$'\t'}"
            [[ "${package}" =~ ^[a-z0-9+.-]+(:[a-z0-9]+)?$ &&
                "${status}" =~ ^[a-z-]+[[:space:]][a-z-]+[[:space:]][a-z-]+$ ]] ||
                panic "malformed output from dpkg-query package enumeration"
            if [[ "${status}" == *" ok installed" ]]; then
                INSTALLED_PACKAGE_NAMES+=("${package}")
            fi
        done <<<"${output}"
    else
        if ! output="$(LC_ALL=C rpm -qa --queryformat '%{NAME}\n')"; then
            panic "failed to enumerate the installed Azure Linux package database"
        fi
        while IFS= read -r line || [[ -n "${line}" ]]; do
            [[ -n "${line}" ]] || continue
            [[ "${line}" =~ ^[A-Za-z0-9+._-]+$ ]] ||
                panic "malformed output from rpm package enumeration"
            INSTALLED_PACKAGE_NAMES+=("${line}")
        done <<<"${output}"
    fi
}

# Selects the exact driver package transaction arguments from the inventory.
prepare_driver_package_plan() {
    local package=""
    DRIVER_PACKAGE_PLAN=()
    for package in "${INSTALLED_PACKAGE_NAMES[@]}"; do
        if [[ "${PLATFORM}" == "ubuntu" ]]; then
            [[ "${package}" =~ ^${UBUNTU_DRIVER_PACKAGE_FAMILY}-[a-z0-9+.-]+$ ]] &&
                DRIVER_PACKAGE_PLAN+=("${package}")
        elif [[ "${package}" == "${AZURE_LINUX_DRIVER_PACKAGE_FAMILY}" ||
            "${package}" =~ ^${AZURE_LINUX_DRIVER_PACKAGE_FAMILY}-[a-z0-9+._-]+$ ]]; then
            DRIVER_PACKAGE_PLAN+=("${package}")
        fi
    done
    return 0
}

# Selects the exact resilient API package transaction arguments from inventory.
prepare_api_package_plan() {
    local package=""
    local development="${API_DEVELOPMENT_PACKAGES[${PLATFORM}]}"
    API_PACKAGE_PLAN=()
    for package in "${INSTALLED_PACKAGE_NAMES[@]}"; do
        if [[ "${package}" == "${API_RUNTIME_PACKAGE}" ||
            "${package}" == "${development}" ]]; then
            API_PACKAGE_PLAN+=("${package}")
        fi
    done
    return 0
}

# Unloads an exact loaded module after API removal and before driver removal.
unload_driver_module() {
    local module_path="${SYS_MODULE_ROOT}/${MODULE_NAME}"
    if ! path_entry_exists "${module_path}"; then
        log_info "AziHSM kernel module is already unloaded."
        return
    fi
    [[ -d "${module_path}" && ! -L "${module_path}" ]] ||
        panic "unexpected AziHSM module path type: ${module_path}"
    log_info "Unloading the AziHSM kernel module."
    if ! execute_command "${MODPROBE_PATH}" -r "${MODULE_NAME}"; then
        panic "failed to unload azihsm; please stop applications holding /dev/azihsm* or /dev/azihsm-mgmt* and retry"
    fi
    if [[ -e "${module_path}" ]]; then
        panic "azihsm remains loaded; please stop applications holding /dev/azihsm* or /dev/azihsm-mgmt* and retry"
    fi
}

# Removes exact driver families through each platform's native package manager.
remove_driver_packages() {
    if [[ "${#DRIVER_PACKAGE_PLAN[@]}" -eq 0 ]]; then
        if [[ "${PLATFORM}" == "ubuntu" ]]; then
            log_info "No installed AziHSM Ubuntu driver packages were found."
        else
            log_info "No installed AziHSM Azure Linux driver packages were found."
        fi
        return
    fi

    if [[ "${PLATFORM}" == "ubuntu" ]]; then
        log_info "Removing AziHSM Ubuntu driver packages: ${DRIVER_PACKAGE_PLAN[*]}."
        if ! execute_command env DEBIAN_FRONTEND=noninteractive \
            apt-get remove -y -- "${DRIVER_PACKAGE_PLAN[@]}"; then
            panic "failed to remove AziHSM Ubuntu driver packages"
        fi
        return
    fi

    log_info "Removing AziHSM Azure Linux driver packages: ${DRIVER_PACKAGE_PLAN[*]}."
    if ! execute_command tdnf --noautoremove remove -y \
        "${DRIVER_PACKAGE_PLAN[@]}"; then
        panic "failed to remove AziHSM Azure Linux driver packages"
    fi
}

# Removes only the two exact resilient API package names for the platform.
remove_api_packages() {
    if [[ "${#API_PACKAGE_PLAN[@]}" -eq 0 ]]; then
        log_info "No installed AziHSM resilient API packages were found."
        return
    fi
    log_info "Removing AziHSM resilient API packages: ${API_PACKAGE_PLAN[*]}."
    if [[ "${PLATFORM}" == "ubuntu" ]]; then
        if ! execute_command env DEBIAN_FRONTEND=noninteractive \
            apt-get remove -y -- "${API_PACKAGE_PLAN[@]}"; then
            panic "failed to remove AziHSM Ubuntu API packages"
        fi
    else
        if ! execute_command tdnf --noautoremove remove -y \
            "${API_PACKAGE_PLAN[@]}"; then
            panic "failed to remove AziHSM Azure Linux API packages"
        fi
    fi
}

# Bounds and strips control characters from package-query diagnostics.
sanitized_diagnostic() {
    local text="$1"
    text="${text//$'\n'/ }"
    text="${text//[$'\001'-$'\037'$'\177']/}"
    printf '%.400s\n' "${text}"
}

# Returns success when a package name is in the resilient API removal plan.
api_plan_contains() {
    local candidate="$1"
    local package=""
    if [[ "${PLATFORM}" == "ubuntu" ]]; then
        candidate="${candidate%%:*}"
    fi
    for package in "${API_PACKAGE_PLAN[@]}"; do
        if [[ "${PLATFORM}" == "ubuntu" ]]; then
            package="${package%%:*}"
        fi
        [[ "${package}" == "${candidate}" ]] && return 0
    done
    return 1
}

# Populates owners from the package database: 0 owned, 1 unowned, 2 error.
query_path_owners() {
    local path="$1"
    local -n owners_ref="$2"
    local output=""
    local status=0
    local line=""
    local token=""
    owners_ref=()
    if [[ "${PLATFORM}" == "ubuntu" ]]; then
        if output="$(LC_ALL=C dpkg-query -S -- "${path}" 2>&1)"; then
            status=0
        else
            status=$?
        fi
        if [[ "${status}" -eq 0 ]]; then
            [[ -n "${output}" ]] || return 2
            while IFS= read -r line || [[ -n "${line}" ]]; do
                [[ "${line}" == *": ${path}" ]] || return 2
                line="${line%": ${path}"}"
                local IFS=', '
                for token in ${line}; do
                    [[ "${token}" =~ ^[a-z0-9+.-]+(:[a-z0-9]+)?$ ]] || return 2
                    owners_ref+=("${token}")
                done
            done <<<"${output}"
            [[ "${#owners_ref[@]}" -gt 0 ]] || return 2
            return 0
        fi
        [[ "${status}" -eq 1 &&
            "${output}" == "dpkg-query: no path found matching pattern ${path}" ]] &&
            return 1
    else
        if output="$(LC_ALL=C rpm -qf --queryformat '%{NAME}\n' -- "${path}" 2>&1)"; then
            status=0
        else
            status=$?
        fi
        if [[ "${status}" -eq 0 ]]; then
            [[ -n "${output}" ]] || return 2
            while IFS= read -r line || [[ -n "${line}" ]]; do
                [[ -n "${line}" ]] || continue
                [[ "${line}" =~ ^[A-Za-z0-9+._-]+$ ]] || return 2
                owners_ref+=("${line}")
            done <<<"${output}"
            [[ "${#owners_ref[@]}" -gt 0 ]] || return 2
            return 0
        fi
        [[ "${status}" -eq 1 &&
            "${output}" == "file ${path} is not owned by any package" ]] &&
            return 1
    fi
    log_error "ownership query failed closed for ${path}: $(sanitized_diagnostic "${output}")"
    return 2
}

# Classifies an artifact: 0 API-planned, 1 unowned, 2 unrelated owner, 3 error.
classify_api_path() {
    local path="$1"
    local -a owners=()
    local status=0
    local owner=""
    if query_path_owners "${path}" owners; then
        status=0
    else
        status=$?
    fi
    case "${status}" in
    1) return 1 ;;
    0)
        for owner in "${owners[@]}"; do
            api_plan_contains "${owner}" || return 2
        done
        return 0
        ;;
    *) return 3 ;;
    esac
}

# Returns success for an existing path entry, including a dangling symlink.
path_entry_exists() {
    [[ -e "$1" || -L "$1" ]]
}

# Canonicalizes an existing fixed candidate parent. Missing parents are normal;
# existing parents must resolve safely to the accepted directory path model.
canonicalize_api_parent() {
    local parent="$1"
    local output_name="$2"
    local resolved=""
    local -n output_ref="${output_name}"
    output_ref=""
    [[ "${parent}" =~ ^/[A-Za-z0-9_+./-]+$ ]] ||
        panic "API candidate parent contains unsafe path characters: ${parent}"
    if ! path_entry_exists "${parent}"; then
        return 1
    fi
    resolved="$(realpath -e -- "${parent}")" ||
        panic "failed to resolve API candidate parent: ${parent}"
    [[ "${resolved}" =~ ^/[A-Za-z0-9_+./-]+$ && -d "${resolved}" &&
        ! -L "${resolved}" ]] ||
        panic "API candidate parent did not resolve to a safe directory: ${parent}"
    output_ref="${resolved}"
}

# Validates an existing discovered artifact's type before it is planned.
validate_api_artifact_type() {
    local path="$1"
    local kind="$2"
    local target=""
    if [[ "${kind}" == "library" && "${path##*/}" == "${API_LIBRARY_NAME}" ]]; then
        [[ -L "${path}" ]] ||
            panic "API linker entry is not a symlink and was left untouched: ${path}"
        target="$(readlink -- "${path}")" ||
            panic "failed to read API linker symlink: ${path}"
        [[ "${target}" == "${API_LIBRARY_SONAME}" ]] ||
            panic "API linker symlink has unexpected target '${target}' and was left untouched: ${path}"
    else
        [[ -f "${path}" && ! -L "${path}" ]] ||
            panic "API artifact has an unexpected type and was left untouched: ${path}"
    fi
}

# Plans one existing exact artifact by ownership: preserve, package-expect, or stage.
classify_and_plan() {
    local path="$1"
    local kind="$2"
    local backup=""
    local category=0
    if ! path_entry_exists "${path}"; then
        log_info "API artifact became absent before ownership planning: ${path}"
        return
    fi
    if classify_api_path "${path}"; then
        category=0
    else
        category=$?
    fi
    # Planned API packages own their library symlinks and remove them themselves.
    # All other entries retain the strict local artifact type checks.
    if [[ "${category}" -ne 0 || "${kind}" != library || ! -L "${path}" ]]; then
        validate_api_artifact_type "${path}" "${kind}"
    fi
    case "${category}" in
    3)
        panic "cannot safely determine package ownership for ${path}"
        ;;
    2)
        log_info "Preserving API artifact owned by an unrelated package: ${path}"
        ;;
    0)
        API_PACKAGE_PLANNED_PATHS+=("${path}")
        log_info "Expecting package removal to delete owned API artifact: ${path}"
        ;;
    1)
        choose_backup_path "${path}" backup
        LOCAL_PATH_KINDS+=("${kind}")
        LOCAL_PATH_DESTINATIONS+=("${path}")
        LOCAL_PATH_BACKUPS+=("${backup}")
        LOCAL_PATH_MOVED+=(false)
        if [[ "${kind}" == "library" ]]; then
            LOCAL_PLAN_REQUIRES_LDCONFIG=true
        fi
        ;;
    esac
    return 0
}

# Builds, classifies, and plans deterministic exact API candidates before mutation.
prepare_local_cleanup() {
    local -a directories=()
    local -a basenames=()
    local -a candidates=()
    local -a kinds=()
    local -A seen=()
    local index=0
    local kind=""
    local parent=""
    local resolved_parent=""
    local basename=""
    local path=""
    API_PACKAGE_PLANNED_PATHS=()
    LOCAL_PATH_KINDS=()
    LOCAL_PATH_DESTINATIONS=()
    LOCAL_PATH_BACKUPS=()
    LOCAL_PATH_MOVED=()
    LOCAL_PLAN_REQUIRES_LDCONFIG=false

    for kind in library header; do
        if [[ "${kind}" == library ]]; then
            directories=("${API_LIBRARY_DIRECTORIES[@]}")
            basenames=("${API_LIBRARY_SONAME}" "${API_LIBRARY_NAME}")
        else
            directories=("${API_HEADER_DIRECTORIES[@]}")
            basenames=("${API_HEADER_NAME}")
        fi
        for parent in "${directories[@]}"; do
            canonicalize_api_parent "${parent}" resolved_parent || continue
            for basename in "${basenames[@]}"; do
                path="${resolved_parent}/${basename}"
                [[ -z "${seen[${path}]+x}" ]] || continue
                seen["${path}"]=1
                candidates+=("${path}")
                kinds+=("${kind}")
            done
        done
    done

    for ((index = 0; index < ${#candidates[@]}; index++)); do
        path="${candidates[index]}"
        path_entry_exists "${path}" || continue
        classify_and_plan "${path}" "${kinds[index]}"
    done

    if [[ "${LOCAL_PLAN_REQUIRES_LDCONFIG}" == true ]]; then
        [[ -f "${LDCONFIG}" && ! -L "${LDCONFIG}" && -x "${LDCONFIG}" ]] ||
            panic "ldconfig is not an executable regular file: ${LDCONFIG}"
    fi
}

# Chooses a same-directory hidden backup path without overwriting an entry.
choose_backup_path() {
    local destination="$1"
    local output_name="$2"
    local candidate=""
    local attempt=0
    local -n output_ref="${output_name}"
    while [[ "${attempt}" -lt 100 ]]; do
        candidate="${destination%/*}/.azihsm-uninstall.${destination##*/}.$$.$RANDOM.${attempt}"
        if ! path_entry_exists "${candidate}"; then
            # shellcheck disable=SC2034  # Nameref output is read by the caller.
            output_ref="${candidate}"
            return
        fi
        attempt=$((attempt + 1))
    done
    panic "failed to choose a unique backup path beside ${destination}"
}

# Restores renamed entries in reverse and refreshes the linker cache if needed.
rollback_local_cleanup() {
    local failed=false
    local index=0
    local backup=""
    local destination=""
    for ((index = ${#LOCAL_PATH_DESTINATIONS[@]} - 1; index >= 0; index--)); do
        [[ "${LOCAL_PATH_MOVED[index]}" == true ]] || continue
        backup="${LOCAL_PATH_BACKUPS[index]}"
        destination="${LOCAL_PATH_DESTINATIONS[index]}"
        if [[ ! -e "${backup}" && ! -L "${backup}" ]]; then
            LOCAL_PATH_MOVED[index]=false
            continue
        fi
        if execute_command mv -Tn -- "${backup}" "${destination}" &&
            ! path_entry_exists "${backup}" &&
            path_entry_exists "${destination}"; then
            LOCAL_PATH_MOVED[index]=false
        else
            log_error "rollback failed; recover ${destination} from ${backup}"
            failed=true
        fi
    done
    if [[ "${LOCAL_TRANSACTION_LIBRARY_CHANGED}" == true ]]; then
        if ! execute_command "${LDCONFIG}"; then
            log_error "failed to refresh the linker cache during rollback"
            failed=true
        fi
    fi
    [[ "${failed}" == false ]]
}

# Handles EXIT/INT/TERM by rolling back only an active local file transaction.
cleanup_local_transaction() {
    if [[ "${LOCAL_TRANSACTION_ACTIVE}" == true ]]; then
        log_error "local AziHSM API cleanup was interrupted; attempting rollback"
        if rollback_local_cleanup; then
            LOCAL_TRANSACTION_ACTIVE=false
        else
            log_error "rollback was incomplete; reported hidden recovery paths were preserved"
        fi
    fi
}

trap cleanup_local_transaction EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Confirms package removal actually deleted every package-owned API artifact.
verify_packaged_api_paths_removed() {
    local path=""
    for path in "${API_PACKAGE_PLANNED_PATHS[@]}"; do
        if path_entry_exists "${path}"; then
            panic "package-owned API artifact still present after package removal: ${path}"
        fi
    done
}

# Renames exact local entries, refreshes ldconfig, then discards backups.
remove_local_api_entries() {
    local index=0
    local destination=""
    local backup=""
    local kind=""
    local failure=""
    if [[ "${#LOCAL_PATH_DESTINATIONS[@]}" -eq 0 ]]; then
        log_info "No unowned local AziHSM API entries require removal."
        return
    fi

    LOCAL_TRANSACTION_ACTIVE=true
    LOCAL_TRANSACTION_LIBRARY_CHANGED=false
    for ((index = 0; index < ${#LOCAL_PATH_DESTINATIONS[@]}; index++)); do
        destination="${LOCAL_PATH_DESTINATIONS[index]}"
        kind="${LOCAL_PATH_KINDS[index]}"
        backup="${LOCAL_PATH_BACKUPS[index]}"
        log_info "Staging local API ${kind} removal: ${destination}"
        LOCAL_PATH_MOVED[index]=true
        if ! execute_command mv -Tn -- "${destination}" "${backup}" ||
            path_entry_exists "${destination}" ||
            ! path_entry_exists "${backup}"; then
            failure="failed to rename local API ${kind} entry to a recovery path"
            break
        fi
        if [[ "${kind}" == "library" ]]; then
            LOCAL_TRANSACTION_LIBRARY_CHANGED=true
        fi
    done

    if [[ -z "${failure}" && "${LOCAL_TRANSACTION_LIBRARY_CHANGED}" == true ]]; then
        if ! execute_command "${LDCONFIG}"; then
            failure="ldconfig failed after staging local API library removal"
        fi
    fi
    if [[ -n "${failure}" ]]; then
        if rollback_local_cleanup; then
            LOCAL_TRANSACTION_ACTIVE=false
            panic "${failure}; local file changes were rolled back"
        fi
        LOCAL_TRANSACTION_ACTIVE=false
        panic "${failure}; rollback was incomplete and recovery paths were preserved"
    fi

    LOCAL_TRANSACTION_ACTIVE=false
    for ((index = 0; index < ${#LOCAL_PATH_BACKUPS[@]}; index++)); do
        backup="${LOCAL_PATH_BACKUPS[index]}"
        [[ -n "${backup}" ]] || continue
        if ! execute_command rm -f -- "${backup}"; then
            panic "local entry was removed but its hidden backup could not be deleted: ${backup}"
        fi
        LOCAL_PATH_MOVED[index]=false
    done
    log_info "Removed validated unowned local AziHSM API entries."
}

# Runs the fail-closed uninstall phases in the required mutation order.
main() {
    parse_arguments "$@"
    require_root

    print_section_header "Environment Detection"
    detect_supported_architecture
    detect_platform
    validate_paths
    printf '\n'

    if [[ "${SKIP_DRIVER}" == true && "${SKIP_API}" == true ]]; then
        log_info "All effective removals are skipped; no platform mutations were performed."
        log_info "Microsoft repositories were retained."
        return
    fi

    print_section_header "Uninstall Planning"
    validate_prerequisites
    inventory_installed_packages
    if [[ "${SKIP_DRIVER}" == false ]]; then
        prepare_driver_package_plan
    fi
    if [[ "${SKIP_API}" == false ]]; then
        prepare_api_package_plan
        prepare_local_cleanup
    fi
    printf '\n'

    # We uninstall in reverse order of installation.
    # Because the API was installed *after* the driver (and it depends on the
    # driver), we remove this first.
    print_section_header "AziHSM API Uninstall"
    if [[ "${SKIP_API}" == false ]]; then
        remove_api_packages
        verify_packaged_api_paths_removed
        remove_local_api_entries
    else
        log_info "Skipping AziHSM API removal."
    fi
    printf '\n'

    # Next, unload the driver module.
    print_section_header "AziHSM Driver Uninstall"
    if [[ "${SKIP_DRIVER}" == false ]]; then
        unload_driver_module
    fi

    # Driver packages are removed last.
    if [[ "${SKIP_DRIVER}" == false ]]; then
        remove_driver_packages
    else
        log_info "Skipping AziHSM driver removal."
    fi
    printf '\n'

    log_info "AziHSM uninstall completed."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
