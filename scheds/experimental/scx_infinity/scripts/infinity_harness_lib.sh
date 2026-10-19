#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_harness_lib.sh - shared helpers for the scx_infinity harnesses.
#
# This file is sourced, never executed. It provides:
#
#   - JSON Lines output, one record per check,
#   - an exit trap that stops workers, the scheduler and cgroups,
#   - fail-closed precondition helpers,
#   - cgroup v2, scheduler, dmesg, statistics and NUMA helpers.
#
# Every harness exits with one of these codes:
#
#   0  every check passed
#   1  a check failed
#   2  a required precondition could not be verified (BLOCKED)
#
# A harness never reports PASS for a check it did not run. A missing tool,
# a missing kernel feature or a non-virtual machine is BLOCKED.

export LC_ALL=C

HARNESS_NAME="${HARNESS_NAME:-harness}"
HARNESS_TMP=""
HARNESS_JSON_OUT=""
HARNESS_STATUS=0
HARNESS_PASS=0
HARNESS_FAIL=0
HARNESS_BLOCKED=0
HARNESS_CGROUP_ROOT=""
HARNESS_CGROUP_SUBTREE_ADDED=0
HARNESS_WORKER_PIDS=()
HARNESS_LAST_PID=""
HARNESS_SCHED_PID=""
HARNESS_SCHED_RC=""
HARNESS_CLEANUP=()

# Escape one string for a JSON string value.
json_escape() {
    local text=${1-}

    text=${text//\\/\\\\}
    text=${text//\"/\\\"}
    text=${text//$'\n'/\\n}
    text=${text//$'\r'/\\r}
    text=${text//$'\t'/\\t}
    printf '%s' "$text"
}

# Print one JSON Lines record. EXTRA is a raw JSON fragment without the
# leading comma.
json_emit() {
    local -r event="$1"
    local -r status="$2"
    local -r check="$3"
    local -r detail="$4"
    local -r extra="${5-}"
    local line

    line=$(printf '{"harness":"%s","event":"%s","status":"%s","check":"%s","detail":"%s"' \
        "$(json_escape "$HARNESS_NAME")" "$(json_escape "$event")" \
        "$(json_escape "$status")" "$(json_escape "$check")" \
        "$(json_escape "$detail")")
    if [[ -n "$extra" ]]; then
        line="$line,$extra"
    fi
    line="$line}"
    printf '%s\n' "$line"
    if [[ -n "$HARNESS_JSON_OUT" ]]; then
        printf '%s\n' "$line" >>"$HARNESS_JSON_OUT"
    fi
}

# Emit one informational record. It does not change the counters.
note() {
    local -r check="$1"
    local -r detail="$2"
    local -r extra="${3-}"

    json_emit note INFO "$check" "$detail" "$extra"
}

# Record one check and update the counters. EXTRA is raw JSON.
record() {
    local -r status="$1"
    local -r check="$2"
    local -r detail="$3"
    local -r extra="${4-}"

    case "$status" in
        PASS)
            HARNESS_PASS=$((HARNESS_PASS + 1))
            ;;
        FAIL)
            HARNESS_FAIL=$((HARNESS_FAIL + 1))
            HARNESS_STATUS=1
            ;;
        BLOCKED)
            HARNESS_BLOCKED=$((HARNESS_BLOCKED + 1))
            if (( HARNESS_STATUS == 0 )); then
                HARNESS_STATUS=2
            fi
            ;;
        *)
            HARNESS_FAIL=$((HARNESS_FAIL + 1))
            HARNESS_STATUS=1
            ;;
    esac
    json_emit check "$status" "$check" "$detail" "$extra"
}

# Add one shell command to the cleanup stack. The stack runs in reverse
# order on exit. Quote the command for eval.
cleanup_push() {
    HARNESS_CLEANUP+=("$1")
}

harness_cleanup_run() {
    local i

    for (( i=${#HARNESS_CLEANUP[@]} - 1; i >= 0; i-- )); do
        eval "${HARNESS_CLEANUP[i]}" >/dev/null 2>&1 || true
    done
    HARNESS_CLEANUP=()
}

harness_summary() {
    local status

    case "$HARNESS_STATUS" in
        0)
            status=PASS
            ;;
        1)
            status=FAIL
            ;;
        *)
            status=BLOCKED
            ;;
    esac
    json_emit summary "$status" summary \
        "$HARNESS_PASS passed, $HARNESS_FAIL failed, $HARNESS_BLOCKED blocked" \
        "$(printf '"pass":%d,"fail":%d,"blocked":%d' \
            "$HARNESS_PASS" "$HARNESS_FAIL" "$HARNESS_BLOCKED")"
}

harness_exit() {
    local rc=$?

    trap - EXIT
    harness_cleanup_run
    if (( rc != 0 && HARNESS_STATUS == 0 )); then
        HARNESS_STATUS=1
    fi
    harness_summary
    if (( HARNESS_STATUS == 0 )); then
        exit 0
    fi
    if (( HARNESS_STATUS == 2 )); then
        exit 2
    fi
    exit 1
}

# Initialise one harness, its temporary directory and its exit trap.
harness_init() {
    HARNESS_NAME=${1:?harness name}
    HARNESS_TMP=$(mktemp -d "${HARNESS_TMP_ROOT:-${TMPDIR:-/tmp}}/scx-infinity-${HARNESS_NAME}.XXXXXX")
    cleanup_push "rm -rf -- $(printf '%q' "$HARNESS_TMP")"
    cleanup_push 'stop_all_workers'
    trap harness_exit EXIT
}

# ---------------------------------------------------------------------
# Preconditions. Each helper records PASS or BLOCKED and returns non-zero
# when the item cannot be verified.
# ---------------------------------------------------------------------

require_root() {
    if (( EUID != 0 )); then
        record BLOCKED root "run as root inside the disposable VM"
        return 1
    fi
    record PASS root "euid=0"
}

require_cmd() {
    local -r name="$1"
    local path

    if ! path=$(command -v "$name" 2>/dev/null); then
        record BLOCKED "cmd:$name" "required command is missing"
        return 1
    fi
    record PASS "cmd:$name" "$path"
}

require_file() {
    local -r path="$1"

    if [[ ! -r "$path" ]]; then
        record BLOCKED "file:$path" "required file is missing or unreadable"
        return 1
    fi
    record PASS "file:$path" "readable"
}

require_writable_file() {
    local -r path="$1"

    if [[ ! -w "$path" ]]; then
        record BLOCKED "file:$path" "required file is missing or read-only"
        return 1
    fi
    record PASS "file:$path" "writable"
}

# The destructive harnesses need an explicit opt-in and a real VM. A
# container or a host is refused, because it cannot be recovered after a
# broken scheduler load.
require_disposable_vm() {
    local virt=""
    local vendor=""
    local product=""

    if [[ "${SCX_INFINITY_VM:-0}" != "1" ]]; then
        record BLOCKED vm "SCX_INFINITY_VM=1 is not set; refusing destructive tests outside a disposable VM"
        return 1
    fi
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt --vm 2>/dev/null || true)
    fi
    if [[ -z "$virt" || "$virt" == "none" ]]; then
        vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
        product=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
        case "$vendor $product" in
            *QEMU*|*KVM*|*VMware*|*VirtualBox*|*Xen*|*Amazon*|*Google*|*Microsoft*|*Bochs*|*Proxmox*)
                virt="dmi"
                ;;
        esac
    fi
    if [[ -z "$virt" || "$virt" == "none" ]]; then
        record BLOCKED vm "no virtual machine detected; destructive tests need a recoverable VM"
        return 1
    fi
    record PASS vm "virtualization=$virt"
}

# Return the cgroup v2 mount point on stdout, or non-zero.
cgroup2_root() {
    local root=""
    local fstype=""

    if [[ -n "$HARNESS_CGROUP_ROOT" ]]; then
        printf '%s\n' "$HARNESS_CGROUP_ROOT"
        return 0
    fi
    if [[ -d /sys/fs/cgroup ]]; then
        fstype=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)
        if [[ "$fstype" == "cgroup2fs" ]]; then
            root=/sys/fs/cgroup
        fi
    fi
    if [[ -z "$root" ]]; then
        root=$(awk '$3 == "cgroup2" { print $2; exit }' /proc/mounts 2>/dev/null || true)
    fi
    if [[ -z "$root" ]]; then
        return 1
    fi
    HARNESS_CGROUP_ROOT=$root
    printf '%s\n' "$root"
}

cgroup_revert_subtree() {
    local -r root="${HARNESS_CGROUP_ROOT:-}"

    if (( HARNESS_CGROUP_SUBTREE_ADDED )) && [[ -n "$root" ]]; then
        printf -- '-cpu\n' >"$root/cgroup.subtree_control" 2>/dev/null || true
    fi
}

cgroup_enable_cpu_at() {
    local -r path="$1"
    local current=""

    current=$(<"$path/cgroup.subtree_control") || return 1
    if [[ " $current " == *" cpu "* ]]; then
        return 0
    fi
    printf '+cpu\n' >"$path/cgroup.subtree_control" 2>/dev/null
}

cgroup_enable_cpu() {
    local -r root="$1"
    local current=""

    current=$(<"$root/cgroup.subtree_control") || {
        record BLOCKED cgroup_subtree "cannot read $root/cgroup.subtree_control"
        return 1
    }
    if [[ " $current " == *" cpu "* ]]; then
        record PASS cgroup_subtree "cpu controller already enabled"
        return 0
    fi
    if ! printf '+cpu\n' >"$root/cgroup.subtree_control" 2>/dev/null; then
        record BLOCKED cgroup_subtree "cannot enable the cpu controller in $root/cgroup.subtree_control"
        return 1
    fi
    HARNESS_CGROUP_SUBTREE_ADDED=1
    cleanup_push 'cgroup_revert_subtree'
    record PASS cgroup_subtree "cpu controller enabled"
}

# Verify the cgroup pieces the harnesses need: the cpu controller, the
# cpu.weight, cpu.max and cpu.idle files, cpu.max.burst, and the cpu.stat
# keys that the measurements read. The probe cgroup is removed by the
# cleanup stack.
require_cgroup_cpu() {
    local root=""
    local probe=""
    local missing=""
    local controllers=""
    local key=""

    if ! root=$(cgroup2_root); then
        record BLOCKED cgroup2 "no cgroup v2 mount found"
        return 1
    fi
    record PASS cgroup2 "$root"
    controllers=$(<"$root/cgroup.controllers") || true
    if [[ " $controllers " != *" cpu "* ]]; then
        record BLOCKED cgroup_cpu "cpu is not listed in $root/cgroup.controllers"
        return 1
    fi
    if ! cgroup_enable_cpu "$root"; then
        return 1
    fi

    probe="$root/scx-infinity-probe.$$"
    if ! mkdir -- "$probe" 2>/dev/null; then
        record BLOCKED cgroup_probe "cannot create $probe"
        return 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$probe") 2>/dev/null || true"

    for key in cpu.weight cpu.max cpu.max.burst cpu.idle cpu.stat; do
        if [[ ! -r "$probe/$key" ]]; then
            missing="$missing $key"
        fi
    done
    if [[ -n "$missing" ]]; then
        record BLOCKED cgroup_cpu "the probe cgroup lacks:$missing"
        return 1
    fi
    for key in usage_usec nr_periods nr_throttled throttled_usec; do
        if ! grep -qw "$key" "$probe/cpu.stat" 2>/dev/null; then
            missing="$missing $key"
        fi
    done
    if [[ -n "$missing" ]]; then
        record BLOCKED cgroup_cpu "cpu.stat lacks:$missing"
        return 1
    fi
    record PASS cgroup_cpu "cpu.weight cpu.max cpu.max.burst cpu.idle and the cpu.stat keys are present"
}

# ---------------------------------------------------------------------
# cgroups. The value-returning helpers print only their value.
# ---------------------------------------------------------------------

cgroup_create() {
    local -r parent="$1"
    local -r name="$2"
    local path="$parent/$name"

    if ! mkdir -- "$path" 2>/dev/null; then
        return 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$path") 2>/dev/null || true"
    printf '%s\n' "$path"
}

cgroup_write() {
    local -r path="$1"
    local -r file="$2"
    local -r value="$3"

    printf '%s\n' "$value" >"$path/$file" 2>/dev/null
}

cgroup_read() {
    local -r path="$1"
    local -r file="$2"

    cat "$path/$file" 2>/dev/null
}

cgroup_procs_empty() {
    local -r path="$1"
    local text=""

    text=$(<"$path/cgroup.procs") || return 1
    [[ -z "${text//[[:space:]]/}" ]]
}

cpu_stat_value() {
    local -r path="$1"
    local -r key="$2"

    awk -v key="$key" '$1 == key { print $2; exit }' "$path/cpu.stat" 2>/dev/null
}

# Start one workload in a cgroup, pinned to one CPU. Print the PID.
start_worker() {
    local -r cg="$1"
    local -r cpu="$2"
    local -r log="$3"
    local pid

    shift 3
    if [[ "$cpu" == "any" ]]; then
        "$@" >"$log" 2>&1 &
    else
        taskset -c "$cpu" "$@" >"$log" 2>&1 &
    fi
    pid=$!
    if ! printf '%s\n' "$pid" >"$cg/cgroup.procs" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    fi
    HARNESS_WORKER_PIDS+=("$pid")
    HARNESS_LAST_PID=$pid
    printf '%s\n' "$pid"
}

stop_worker() {
    local -r pid="$1"

    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

stop_all_workers() {
    local pid

    if (( ${#HARNESS_WORKER_PIDS[@]} == 0 )); then
        return 0
    fi
    for pid in "${HARNESS_WORKER_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "${HARNESS_WORKER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    HARNESS_WORKER_PIDS=()
}

join_workers() {
    local pid
    local rc=0

    if (( ${#HARNESS_WORKER_PIDS[@]} == 0 )); then
        return 0
    fi
    for pid in "${HARNESS_WORKER_PIDS[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            rc=1
        fi
    done
    HARNESS_WORKER_PIDS=()
    return "$rc"
}

# ---------------------------------------------------------------------
# Scheduler.
# ---------------------------------------------------------------------

sched_state() {
    cat /sys/kernel/sched_ext/state 2>/dev/null || true
}

wait_for_sched_state() {
    local -r want="$1"
    local -r seconds="$2"
    local i

    for (( i=0; i < seconds * 20; i++ )); do
        if [[ "$(sched_state)" == "$want" ]]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

start_scheduler() {
    local -r bin="$1"
    local -r log="$2"

    shift 2
    "$bin" "$@" >"$log" 2>&1 &
    HARNESS_SCHED_PID=$!
    cleanup_push 'stop_scheduler'
}

# Stop the scheduler with SIGINT, then SIGKILL after ten seconds. Store the
# exit status in HARNESS_SCHED_RC. Safe to call more than once.
stop_scheduler() {
    local pid="${HARNESS_SCHED_PID:-}"
    local i

    if [[ -z "$pid" ]]; then
        return 0
    fi
    HARNESS_SCHED_PID=""
    if kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        for (( i=0; i < 200; i++ )); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    set +e
    wait "$pid" 2>/dev/null
    HARNESS_SCHED_RC=$?
    set -e
}

scheduler_alive() {
    [[ -n "${HARNESS_SCHED_PID:-}" ]] && kill -0 "$HARNESS_SCHED_PID" 2>/dev/null
}

# Return the path of the scheduler binary. The environment variable
# SCX_INFINITY_BIN wins, then the release and debug build.
resolve_scheduler() {
    local bin="${SCX_INFINITY_BIN:-}"
    local root=""
    local candidate=""

    if [[ -n "$bin" ]]; then
        if [[ -x "$bin" ]]; then
            printf '%s\n' "$bin"
            return 0
        fi
        return 1
    fi
    root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || true)
    if [[ -z "$root" ]]; then
        return 1
    fi
    for candidate in "$root/target/release/scx_infinity" "$root/target/debug/scx_infinity"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------
# Statistics from the loader log.
# ---------------------------------------------------------------------

stats_line() {
    grep -F 'inserts: head=' "$1" 2>/dev/null | tail -n 1 || true
}

# Read one counter from the newest statistics line. Print 0 when the line
# is missing.
stat_value() {
    local -r log="$1"
    local -r key="$2"
    local line=""
    local value=""

    line=$(stats_line "$log")
    if [[ -z "$line" ]]; then
        printf '0\n'
        return 0
    fi
    value=$(printf '%s\n' "$line" |
        grep -oE "(^|[[:space:]])${key}=[0-9-]+" |
        tail -n 1 |
        sed 's/.*=//' || true)
    printf '%s\n' "${value:-0}"
}

# ---------------------------------------------------------------------
# dmesg.
# ---------------------------------------------------------------------

require_dmesg() {
    if ! dmesg >/dev/null 2>&1; then
        record BLOCKED dmesg "dmesg is not readable; the scheduler error check cannot run"
        return 1
    fi
    record PASS dmesg "readable"
}

dmesg_lines() {
    dmesg 2>/dev/null | wc -l
}

# Print the new kernel lines that match a scheduler fault. Empty output is
# a clean run.
dmesg_new_faults() {
    local -r baseline="$1"

    dmesg 2>/dev/null | tail -n "+$((baseline + 1))" |
        grep -Ei 'scx_bpf_error|runnable task stall|watchdog|BUG:|WARNING:|Oops|Call Trace' || true
}

# ---------------------------------------------------------------------
# NUMA and affinity helpers.
# ---------------------------------------------------------------------

# Print the number of CPUs in a kernel cpulist such as 0-3,8,10-11.
cpulist_count() {
    local -r list="$1"

    awk -v list="$list" 'BEGIN {
        n = split(list, part, ",")
        count = 0
        for (i = 1; i <= n; i++) {
            if (part[i] ~ /-/) {
                split(part[i], range, "-")
                count += range[2] - range[1] + 1
            } else if (part[i] != "") {
                count += 1
            }
        }
        print count
    }'
}

cpu_in_list() {
    local -r cpu="$1"
    local -r list="$2"

    awk -v cpu="$cpu" -v list="$list" 'BEGIN {
        n = split(list, part, ",")
        for (i = 1; i <= n; i++) {
            if (part[i] ~ /-/) {
                split(part[i], range, "-")
                if (cpu >= range[1] && cpu <= range[2]) {
                    exit 0
                }
            } else if (cpu == part[i]) {
                exit 0
            }
        }
        exit 1
    }'
}

cpulist_first() {
    local -r list="$1"

    awk -v list="$list" 'BEGIN {
        n = split(list, part, ",")
        if (n < 1 || part[1] == "") {
            exit 1
        }
        if (part[1] ~ /-/) {
            split(part[1], range, "-")
            print range[1]
        } else {
            print part[1]
        }
    }'
}

# Print one CPU per line from a kernel cpulist.
cpulist_expand() {
    local -r list="$1"

    awk -v list="$list" 'BEGIN {
        n = split(list, part, ",")
        for (i = 1; i <= n; i++) {
            if (part[i] ~ /-/) {
                split(part[i], range, "-")
                for (cpu = range[1]; cpu <= range[2]; cpu++) {
                    print cpu
                }
            } else if (part[i] != "") {
                print part[i]
            }
        }
    }'
}

numa_nodes_online() {
    cat /sys/devices/system/node/online 2>/dev/null || true
}

node_cpulist() {
    cat "/sys/devices/system/node/node$1/cpulist" 2>/dev/null || true
}

cpu_llc_list() {
    cat "/sys/devices/system/cpu/cpu$1/cache/index3/shared_cpu_list" 2>/dev/null || true
}

require_two_nodes() {
    local online=""
    local count=0

    online=$(numa_nodes_online)
    if [[ -z "$online" ]]; then
        record BLOCKED numa "the NUMA node online file is missing"
        return 1
    fi
    count=$(cpulist_count "$online")
    if (( count < 2 )); then
        record BLOCKED numa "only $count NUMA node(s) online; the placement check needs two"
        return 1
    fi
    record PASS numa "online=$online"
}

# Numeric helpers. They compare with awk, so the harnesses need no bc.
num_in_range() {
    local -r value="$1"
    local -r low="$2"
    local -r high="$3"

    awk -v value="$value" -v low="$low" -v high="$high" \
        'BEGIN { exit !(value >= low && value <= high) }'
}

fp_ratio() {
    local -r a="$1"
    local -r b="$2"

    awk -v a="$a" -v b="$b" 'BEGIN {
        if (a <= 0) {
            print "999"
        } else {
            printf "%.4f", b / a
        }
    }'
}

fp_scale() {
    local -r value="$1"
    local -r divisor="$2"

    awk -v value="$value" -v divisor="$divisor" 'BEGIN {
        if (divisor <= 0) {
            print "0"
        } else {
            printf "%.4f", value / divisor
        }
    }'
}

median_of() {
    if (($# == 0)); then
        printf '0\n'
        return 0
    fi
    printf '%s\n' "$@" | sort -n | awk '
        { value[NR] = $1 }
        END {
            if (NR % 2 == 1) {
                printf "%.4f", value[(NR + 1) / 2]
            } else {
                printf "%.4f", (value[NR / 2] + value[NR / 2 + 1]) / 2
            }
        }'
}
