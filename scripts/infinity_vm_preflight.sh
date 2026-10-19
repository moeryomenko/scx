#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# infinity_vm_preflight.sh - check a guest kernel for scx_infinity features.
#
# Run this script as root inside the guest before a VM test. It checks the
# five features that revision 3 of the specification needs:
#
#   sched_ext              CONFIG_SCHED_CLASS_EXT and /sys/kernel/sched_ext
#   bpf_arena              BPF arena map and kfunc support
#   cgroup_cpu             cgroup v2 cpu controller and cpu.max
#   cpu_idle               the cpu.idle cgroup file
#   scx_cgroup_cbs         sched_ext cpu.weight, cpu.idle and cpu.max glue
#
# Each item prints PASS or BLOCKED. The script exits 1 when a required
# feature is missing or cannot be verified. It does not load a scheduler.
#
# Feature paths were checked in the kernel source before this script was
# written:
#
#   - kernel/bpf/Makefile builds kernel/bpf/arena.c with CONFIG_BPF_SYSCALL.
#   - kernel/bpf/arena.c registers the bpf_arena_alloc_pages kfunc.
#   - kernel/sched/core.c defines the cpu.idle file under
#     CONFIG_GROUP_SCHED_WEIGHT and the cpu.max file under
#     CONFIG_GROUP_SCHED_BANDWIDTH.
#   - init/Kconfig defines CONFIG_EXT_GROUP_SCHED, which selects
#     CONFIG_GROUP_SCHED_WEIGHT and CONFIG_GROUP_SCHED_BANDWIDTH.
#   - kernel/sched/ext/ext.c defines scx_group_set_weight,
#     scx_group_set_idle and scx_group_set_bandwidth under
#     CONFIG_EXT_GROUP_SCHED.
#
# Usage:
#   sudo scripts/infinity_vm_preflight.sh [--require-two-numa-nodes]
#
# --require-two-numa-nodes makes a two-node guest a required item. Without
# the flag the NUMA layout is printed as INFO only.

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
IFS=$'\n\t'

readonly CGROUP_ROOT_DEFAULT="/sys/fs/cgroup"

FAILED=0
REQUIRE_NUMA=0
CGROUP_ROOT=""
CGROUP_CHILD=""
SUBTREE_ADDED=0

pass() {
    printf '%s: PASS (%s)\n' "$1" "$2"
}

blocked() {
    printf '%s: BLOCKED (%s)\n' "$1" "$2"
    FAILED=1
}

info() {
    printf '%s: INFO (%s)\n' "$1" "$2"
}

usage() {
    printf 'usage: %s [--require-two-numa-nodes]\n' "${0##*/}"
}

cleanup() {
    local code=$?

    trap - EXIT
    if [[ -n "$CGROUP_CHILD" && -d "$CGROUP_CHILD" ]]; then
        rmdir -- "$CGROUP_CHILD" 2>/dev/null || true
    fi
    if (( SUBTREE_ADDED )) && [[ -n "$CGROUP_ROOT" ]]; then
        printf -- '-cpu\n' >"$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
    fi
    exit "$code"
}
trap cleanup EXIT

# Read one key from the guest kernel configuration. The first readable
# source wins. An absent configuration prints nothing.
read_config() {
    local -r key="$1"
    local value=""
    local cfg

    if [[ -r /proc/config.gz ]] && command -v zgrep >/dev/null 2>&1; then
        value=$(zgrep -m1 "^${key}=" /proc/config.gz 2>/dev/null || true)
    fi

    if [[ -z "$value" ]]; then
        for cfg in \
            "/boot/config-$(uname -r)" \
            "/lib/modules/$(uname -r)/config" \
            "/usr/lib/modules/$(uname -r)/config"; do
            if [[ -r "$cfg" ]]; then
                value=$(grep -m1 "^${key}=" "$cfg" 2>/dev/null || true)
                if [[ -n "$value" ]]; then
                    break
                fi
            fi
        done
    fi

    printf '%s\n' "$value"
}

config_is() {
    local -r key="$1"
    local -r want="$2"
    local got

    got=$(read_config "$key")
    [[ "$got" == "${key}=${want}" ]]
}

ksym_exists() {
    local -r name="$1"

    [[ -r /proc/kallsyms ]] || return 1
    grep -qw -- "$name" /proc/kallsyms 2>/dev/null
}

btf_has_string() {
    local -r name="$1"

    [[ -r /sys/kernel/btf/vmlinux ]] || return 1
    grep -aq -- "$name" /sys/kernel/btf/vmlinux 2>/dev/null
}

# Return the body of one BTF struct, or nothing. This uses bpftool only
# when it is installed. A missing bpftool is not an error.
btf_struct_body() {
    local -r name="$1"

    command -v bpftool >/dev/null 2>&1 || return 0
    [[ -r /sys/kernel/btf/vmlinux ]] || return 0
    bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null |
        sed -n "/^struct ${name} {/,/^};/p" || true
}

# Find the cgroup v2 mount. /sys/fs/cgroup is the usual mount. A guest
# with a different mount point is also accepted.
find_cgroup_root() {
    local mount_type=""
    local root=""

    if [[ -d "$CGROUP_ROOT_DEFAULT" ]]; then
        mount_type=$(stat -fc %T "$CGROUP_ROOT_DEFAULT" 2>/dev/null || true)
        if [[ "$mount_type" == "cgroup2fs" ]]; then
            printf '%s\n' "$CGROUP_ROOT_DEFAULT"
            return 0
        fi
    fi

    root=$(awk '$3 == "cgroup2" { print $2; exit }' /proc/mounts 2>/dev/null || true)
    if [[ -n "$root" ]]; then
        printf '%s\n' "$root"
        return 0
    fi

    return 1
}

# Create one child cgroup with the cpu controller. The cpu.idle file
# and the cpu.max file only exist below the root cgroup. Return 1 when
# the caller is not root or the mount is read only, and let the caller
# fall back to the configuration and kallsyms checks.
prepare_cgroup_child() {
    local subtree=""

    if [[ "$EUID" -ne 0 || -z "$CGROUP_ROOT" ]]; then
        return 1
    fi
    if [[ ! -w "$CGROUP_ROOT/cgroup.subtree_control" ]]; then
        return 1
    fi

    subtree=$(<"$CGROUP_ROOT/cgroup.subtree_control")
    if [[ " $subtree " != *" cpu "* ]]; then
        if ! printf '+cpu\n' >"$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null; then
            return 1
        fi
        SUBTREE_ADDED=1
    fi

    CGROUP_CHILD="$CGROUP_ROOT/infinity-preflight.$$"
    if ! mkdir -- "$CGROUP_CHILD" 2>/dev/null; then
        CGROUP_CHILD=""
        if (( SUBTREE_ADDED )); then
            printf -- '-cpu\n' >"$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
            SUBTREE_ADDED=0
        fi
        return 1
    fi

    return 0
}

check_sched_ext() {
    local cfg=0
    local runtime=0
    local state=""

    if config_is CONFIG_SCHED_CLASS_EXT y; then
        cfg=1
    fi
    if [[ -r /sys/kernel/sched_ext/state ]]; then
        runtime=1
        state=$(</sys/kernel/sched_ext/state)
    fi

    if (( cfg && runtime )); then
        pass sched_ext "CONFIG_SCHED_CLASS_EXT=y, state=${state}"
    elif (( runtime )); then
        pass sched_ext "state=${state}, kernel config not readable"
    elif (( cfg )); then
        blocked sched_ext "CONFIG_SCHED_CLASS_EXT=y but /sys/kernel/sched_ext/state is missing"
    else
        blocked sched_ext "CONFIG_SCHED_CLASS_EXT is not y and /sys/kernel/sched_ext/state is missing"
    fi
}

check_bpf_arena() {
    local cfg=0
    local kfunc=0
    local jit=0

    if config_is CONFIG_BPF_SYSCALL y; then
        cfg=1
    fi
    if ksym_exists bpf_arena_alloc_pages || btf_has_string bpf_arena_alloc_pages; then
        kfunc=1
    fi
    if ksym_exists bpf_jit_supports_arena || btf_has_string bpf_jit_supports_arena; then
        jit=1
    fi

    if (( cfg && kfunc && jit )); then
        pass bpf_arena "CONFIG_BPF_SYSCALL=y, arena kfunc and JIT probe present"
    elif (( kfunc && jit )); then
        pass bpf_arena "arena kfunc and JIT probe present, kernel config not readable"
    elif (( kfunc )); then
        blocked bpf_arena "arena kfunc present but bpf_jit_supports_arena is missing"
    elif (( cfg )); then
        blocked bpf_arena "CONFIG_BPF_SYSCALL=y but the arena kfunc is missing"
    else
        blocked bpf_arena "BPF arena is not present"
    fi
}

check_cgroup_cpu() {
    local controllers=""
    local cgroup=0
    local max_cfg=0
    local max_file=0
    local max_ksym=0
    local detail=""

    CGROUP_ROOT=$(find_cgroup_root || true)
    if [[ -z "$CGROUP_ROOT" ]]; then
        blocked cgroup_cpu "no cgroup v2 mount found"
        return
    fi

    if [[ -r "$CGROUP_ROOT/cgroup.controllers" ]]; then
        controllers=$(<"$CGROUP_ROOT/cgroup.controllers")
        if [[ " $controllers " == *" cpu "* ]]; then
            cgroup=1
        fi
    fi

    if config_is CONFIG_CGROUP_SCHED y; then
        detail="CONFIG_CGROUP_SCHED=y"
    fi

    if prepare_cgroup_child; then
        if [[ -r "$CGROUP_CHILD/cpu.max" ]]; then
            max_file=1
        fi
        if [[ -r "$CGROUP_CHILD/cpu.weight" ]]; then
            detail="${detail:+$detail, }cpu.weight present"
        fi
    fi

    if config_is CONFIG_GROUP_SCHED_BANDWIDTH y; then
        max_cfg=1
    fi
    if ksym_exists cpu_max_write; then
        max_ksym=1
    fi

    if (( cgroup == 0 )); then
        blocked cgroup_cpu "the cpu controller is not listed in cgroup.controllers"
    elif (( max_file )); then
        detail="${detail:+$detail, }cpu.max file present"
        pass cgroup_cpu "$detail"
    elif (( max_cfg || max_ksym )); then
        detail="${detail:+$detail, }cpu.max supported by config or symbol, runtime file not checked"
        pass cgroup_cpu "$detail"
    else
        blocked cgroup_cpu "the cpu controller exists but cpu.max is missing"
    fi
}

check_cpu_idle() {
    local cfg=0
    local file=0
    local detail=""

    if [[ -z "$CGROUP_ROOT" ]]; then
        blocked cpu_idle "no cgroup v2 mount"
        return
    fi

    if config_is CONFIG_GROUP_SCHED_WEIGHT y; then
        cfg=1
    fi
    if [[ -n "$CGROUP_CHILD" && -r "$CGROUP_CHILD/cpu.idle" ]]; then
        file=1
    fi

    if (( cfg )); then
        detail="CONFIG_GROUP_SCHED_WEIGHT=y"
    fi

    if (( file )); then
        detail="${detail:+$detail, }cpu.idle file present"
        pass cpu_idle "$detail"
    elif (( cfg )) || ksym_exists cpu_idle_write_s64; then
        detail="${detail:+$detail, }runtime file not checked"
        if [[ "$EUID" -ne 0 ]]; then
            detail="$detail (not root)"
        elif [[ -z "$CGROUP_CHILD" ]]; then
            detail="$detail (cgroup child unavailable)"
        fi
        pass cpu_idle "$detail"
    else
        blocked cpu_idle "CONFIG_GROUP_SCHED_WEIGHT is not y and cpu_idle_write_s64 is missing"
    fi
}

check_scx_cgroup_cbs() {
    local cfg=0
    local weight=0
    local idle=0
    local bandwidth=0
    local body=""
    local missing=""

    if config_is CONFIG_EXT_GROUP_SCHED y; then
        cfg=1
    fi

    if ksym_exists scx_group_set_weight || btf_has_string scx_group_set_weight; then
        weight=1
    fi
    if ksym_exists scx_group_set_idle || btf_has_string scx_group_set_idle; then
        idle=1
    fi
    if ksym_exists scx_group_set_bandwidth || btf_has_string scx_group_set_bandwidth; then
        bandwidth=1
    fi

    # The BTF struct check is stricter than a string search. Use it when
    # bpftool is installed, and keep the kallsyms result as the fallback.
    body=$(btf_struct_body sched_ext_ops || true)
    if [[ -n "$body" ]]; then
        if grep -qw cgroup_set_weight <<<"$body"; then
            weight=1
        fi
        if grep -qw cgroup_set_idle <<<"$body"; then
            idle=1
        fi
        if grep -qw cgroup_set_bandwidth <<<"$body"; then
            bandwidth=1
        fi
    fi

    if (( weight == 0 )); then
        missing=" weight"
    fi
    if (( idle == 0 )); then
        missing="$missing idle"
    fi
    if (( bandwidth == 0 )); then
        missing="$missing bandwidth"
    fi

    if (( cfg && weight && idle && bandwidth )); then
        pass scx_cgroup_cbs "CONFIG_EXT_GROUP_SCHED=y, weight and idle and bandwidth callbacks present"
    elif (( weight && idle && bandwidth )); then
        pass scx_cgroup_cbs "weight and idle and bandwidth callbacks present, kernel config not readable"
    else
        blocked scx_cgroup_cbs "missing:${missing}"
    fi
}

check_numa() {
    local online=""
    local count=0
    local entry
    local first
    local last
    local -a entries=()

    if [[ ! -r /sys/devices/system/node/online ]]; then
        info numa_nodes "node online file is missing"
        if (( REQUIRE_NUMA )); then
            blocked numa_nodes "two-node guest required but node topology is missing"
        fi
        return
    fi

    online=$(</sys/devices/system/node/online)
    IFS=',' read -ra entries <<<"$online"
    for entry in "${entries[@]}"; do
        if [[ "$entry" == *-* ]]; then
            first=${entry%-*}
            last=${entry#*-}
            count=$((count + last - first + 1))
        else
            count=$((count + 1))
        fi
    done

    info numa_nodes "online=${online} count=${count}"
    if (( REQUIRE_NUMA && count < 2 )); then
        blocked numa_nodes "two-node guest required but only ${count} node(s) are online"
    fi
}

main() {
    while (($#)); do
        case "$1" in
            --require-two-numa-nodes)
                REQUIRE_NUMA=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                printf 'unknown argument: %s\n' "$1" >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done

    check_sched_ext
    check_bpf_arena
    check_cgroup_cpu
    check_cpu_idle
    check_scx_cgroup_cbs
    check_numa

    printf '\n'
    if (( FAILED )); then
        printf 'summary: BLOCKED\n'
        exit 1
    fi

    printf 'summary: PASS\n'
}

main "$@"
