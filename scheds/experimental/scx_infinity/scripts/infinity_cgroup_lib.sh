#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_cgroup_lib.sh - cgroup v2 fixtures and measurements shared by
# the scx_infinity harnesses.
#
# This file is sourced after infinity_harness_lib.sh. It provides the
# cgroup tree construction, the controller writes and the runtime reads
# that the cgroup behavior harness needs:
#
#   - one case tree per fixture, removed as a whole,
#   - parent, child and threaded-child creation with the cpu controller
#     enabled at every level that has children,
#   - cpu.weight, cpu.idle, cpu.max and cpu.max.burst writes,
#   - cgroup.type, cgroup.procs and cgroup.threads reads,
#   - per-group cpu.stat usage and per-task runtime from
#     /proc/PID/schedstat,
#   - a monotonic microsecond clock without a fork,
#   - a poll for the first real run of a starved task.
#
# Every value helper prints only its value. Every write helper returns
# non-zero on failure so the caller records FAIL or BLOCKED itself. A
# helper never reports PASS.

: "${HARNESS_NAME:?source infinity_harness_lib.sh before infinity_cgroup_lib.sh}"

# One scheduler accounting tick on the CONFIG_HZ=1000 test guest. The
# feasibility evidence measured a 1.000 ms median tick
# (.agent/tasks/feasibility-v4/evidence.md, AC-5). The move-conservation
# check allows this much skew between the per-group and the per-task
# ledger.
INF_ACCOUNT_TICK_US="${INF_ACCOUNT_TICK_US:-1000}"

# Monotonic-ish wall clock in microseconds. EPOCHREALTIME is a bash
# variable, so the call starts no process. Six fractional digits are
# required; bash prints them.
now_us() {
    local stamp=${EPOCHREALTIME//[!0-9]/}

    printf '%s\n' "$((10#$stamp))"
}

# ---------------------------------------------------------------------
# Tree construction.
#
# The root of one case is a directory under $CGROUP_PARENT. Each case
# removes its own tree, so the fixtures do not share controller state.
# ---------------------------------------------------------------------

# Create one case root and register its removal. Print the path.
cg_case_root() {
    local -r name="${1:?case name}"
    local path=""

    if [[ -z "${CGROUP_PARENT:-}" ]]; then
        return 1
    fi
    path="$CGROUP_PARENT/$name"
    if ! mkdir -- "$path" 2>/dev/null; then
        return 1
    fi
    cleanup_push "cg_remove_tree $(printf '%q' "$path")"
    printf '%s\n' "$path"
}

# Create one child group and print its path.
cg_group() {
    local -r parent="${1:?parent}"
    local -r name="${2:?name}"
    local path="$parent/$name"

    if ! mkdir -- "$path" 2>/dev/null; then
        return 1
    fi
    printf '%s\n' "$path"
}

# Create a threaded child and print its path. The parent turns into
# "domain threaded" once the child is threaded.
cg_threaded_group() {
    local path=""

    if ! path=$(cg_group "$1" "$2"); then
        return 1
    fi
    if ! printf 'threaded\n' >"$path/cgroup.type" 2>/dev/null; then
        return 1
    fi
    printf '%s\n' "$path"
}

# Enable the cpu controller for the children of one group.
cg_enable_subtree() {
    local -r path="${1:?path}"
    local current=""

    current=$(<"$path/cgroup.subtree_control") || return 1
    if [[ " $current " == *" cpu "* ]]; then
        return 0
    fi
    printf '+cpu\n' >"$path/cgroup.subtree_control" 2>/dev/null
}

# Enable the cpu controller for the children of one group and report the
# result. Used by the fixtures where a silent failure would change the
# measured tree.
cg_enable_subtree_or_fail() {
    local -r path="$1"
    local -r check="$2"
    local current=""

    if ! cg_enable_subtree "$path"; then
        record FAIL "$check" "cannot enable the cpu controller in $path"
        return 1
    fi
    current=$(<"$path/cgroup.subtree_control") || return 1
    if [[ " $current " != *" cpu "* ]]; then
        record FAIL "$check" "the cpu controller is not listed in $path/cgroup.subtree_control after the write"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------
# Controller writes.
# ---------------------------------------------------------------------

cg_weight() {
    printf '%s\n' "$2" >"$1/cpu.weight" 2>/dev/null
}

cg_idle() {
    printf '%s\n' "$2" >"$1/cpu.idle" 2>/dev/null
}

# cg_max PATH QUOTA [PERIOD]. QUOTA is a number of microseconds or the
# literal "max".
cg_max() {
    local -r path="$1"
    local -r quota="$2"
    local -r period="${3:-100000}"

    if [[ "$quota" == "max" ]]; then
        printf 'max %s\n' "$period" >"$path/cpu.max" 2>/dev/null
    else
        printf '%s %s\n' "$quota" "$period" >"$path/cpu.max" 2>/dev/null
    fi
}

cg_burst() {
    printf '%s\n' "$2" >"$1/cpu.max.burst" 2>/dev/null
}

# ---------------------------------------------------------------------
# Reads.
# ---------------------------------------------------------------------

cg_type() {
    cat "$1/cgroup.type" 2>/dev/null
}

cg_file() {
    cat "$1/$2" 2>/dev/null
}

# True when PID is listed in one of the group's membership files.
cg_has_pid() {
    local -r path="$1"
    local -r file="$2"
    local -r pid="$3"

    grep -qw -- "$pid" "$path/$file" 2>/dev/null
}

# Put one task into a group through cgroup.procs or cgroup.threads.
cg_put_task() {
    local -r path="$1"
    local -r file="$2"
    local -r pid="$3"

    printf '%s\n' "$pid" >"$path/$file" 2>/dev/null
}

# Total CPU time of one group and its descendants, in microseconds.
cg_usage_us() {
    cpu_stat_value "$1" usage_usec
}

# One task's accumulated runtime in microseconds from
# /proc/PID/schedstat. The first field is runtime in nanoseconds.
cg_task_runtime_us() {
    local -r pid="$1"
    local ns=""

    if ! IFS=' ' read -r ns _ <"/proc/$pid/schedstat" 2>/dev/null; then
        return 1
    fi
    if [[ ! "$ns" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    printf '%s\n' "$((ns / 1000))"
}

# The scheduling policy of one task, for example SCHED_IDLE, as chrt
# prints it.
cg_task_policy() {
    chrt -p "$1" 2>/dev/null | sed -n 's/^.*scheduling policy: //p'
}

# Wait for a task to be in WANT_POLICY. chrt sets the policy after fork,
# so a read taken right after the spawn can still see the inherited
# SCHED_OTHER.
cg_wait_task_policy() {
    local -r pid="$1"
    local -r want="$2"
    local -r seconds="$3"
    local i=0

    for (( i = 0; i < seconds * 100; i++ )); do
        if [[ "$(cg_task_policy "$pid")" == "$want" ]]; then
            return 0
        fi
        sleep 0.01
    done
    return 1
}

# Snapshot two group ledgers and three task ledgers in one builtin-only
# pass. Print "a_us b_us task1_us task2_us task3_us". The move check needs
# a snapshot that is shorter than one accounting tick, and awk or cat per
# file would not be.
cg_ledger_snapshot() {
    local -r a="$1"
    local -r b="$2"
    local -r p1="$3"
    local -r p2="$4"
    local -r p3="$5"
    local key=""
    local value=""
    local ua=""
    local ub=""
    local n1=""
    local n2=""
    local n3=""

    while IFS=' ' read -r key value; do
        if [[ "$key" == "usage_usec" ]]; then
            ua=$value
        fi
    done <"$a/cpu.stat"
    while IFS=' ' read -r key value; do
        if [[ "$key" == "usage_usec" ]]; then
            ub=$value
        fi
    done <"$b/cpu.stat"
    IFS=' ' read -r n1 _ <"/proc/$p1/schedstat" || return 1
    IFS=' ' read -r n2 _ <"/proc/$p2/schedstat" || return 1
    IFS=' ' read -r n3 _ <"/proc/$p3/schedstat" || return 1
    if [[ -z "$ua" || -z "$ub" ]]; then
        return 1
    fi
    printf '%s %s %s %s %s\n' \
        "$ua" "$ub" "$((n1 / 1000))" "$((n2 / 1000))" "$((n3 / 1000))"
}

# Print a / (a + b) rounded to six decimals. A zero denominator prints 0,
# so the caller fails the range check instead of dividing by zero.
fp_share() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        total = a + b
        if (total <= 0) {
            print "0"
        } else {
            printf "%.6f", a / total
        }
    }'
}

# ---------------------------------------------------------------------
# Measurements.
# ---------------------------------------------------------------------

# Read the runtime of every PID given on the command line, one line per
# PID, as "pid runtime_us".
cg_task_runtimes() {
    local pid runtime

    for pid in "$@"; do
        if ! runtime=$(cg_task_runtime_us "$pid"); then
            return 1
        fi
        printf '%s %s\n' "$pid" "$runtime"
    done
}

# Start one workload in a group through cgroup.procs or cgroup.threads
# and print its PID. The command runs under taskset when CPU is not
# "any".
cg_start_task() {
    local -r cg="$1"
    local -r cpu="$2"
    local -r file="$3"
    local -r log="$4"
    local pid=""

    shift 4
    if [[ "$cpu" == "any" ]]; then
        "$@" >"$log" 2>&1 &
    else
        taskset -c "$cpu" "$@" >"$log" 2>&1 &
    fi
    pid=$!
    if ! printf '%s\n' "$pid" >"$cg/$file" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    fi
    HARNESS_WORKER_PIDS+=("$pid")
    HARNESS_LAST_PID=$pid
    printf '%s\n' "$pid"
}

# Poll a starved task until it has consumed NEED_US more runtime than
# BASE_US. Print the microseconds that elapsed. Return 0 when the task
# ran, 1 on timeout or on a vanished task.
#
# The loop uses the read builtin and the clock variable, so it starts no
# process per iteration. A polling harness shell must not starve the task
# it measures, so the poll runs unpinned while the measured workers are
# pinned to one CPU.
cg_wait_runtime_growth() {
    local -r pid="$1"
    local -r base_us="$2"
    local -r need_us="$3"
    local -r timeout_us="$4"
    local start=0
    local now=0
    local ns=""
    local runtime=0

    start=${EPOCHREALTIME//[!0-9]/}
    start=$((10#$start))
    while :; do
        if ! IFS=' ' read -r ns _ <"/proc/$pid/schedstat" 2>/dev/null; then
            now=${EPOCHREALTIME//[!0-9]/}
            printf '%s\n' "$((10#$now - start))"
            return 1
        fi
        runtime=$((ns / 1000))
        if (( runtime - base_us >= need_us )); then
            now=${EPOCHREALTIME//[!0-9]/}
            printf '%s\n' "$((10#$now - start))"
            return 0
        fi
        now=${EPOCHREALTIME//[!0-9]/}
        if (( 10#$now - start >= timeout_us )); then
            printf '%s\n' "$((10#$now - start))"
            return 1
        fi
    done
}

# ---------------------------------------------------------------------
# Removal.
# ---------------------------------------------------------------------

# Kill every task below one tree. cgroup.kill exists since Linux 5.14.
cg_kill_tree() {
    local -r path="$1"

    if [[ -w "$path/cgroup.kill" ]]; then
        printf '1\n' >"$path/cgroup.kill" 2>/dev/null || true
    fi
}

# Remove one case tree, deepest directory first, and return 0 only when
# the root is gone. Workers are killed through cgroup.kill, so a broken
# case cannot leak a busy task into the next one.
cg_remove_tree() {
    local -r path="$1"
    local dir=""
    local attempt=0

    if [[ ! -e "$path" ]]; then
        return 0
    fi
    cg_kill_tree "$path"
    for (( attempt = 0; attempt < 4; attempt++ )); do
        find "$path" -depth -type d 2>/dev/null |
            while IFS= read -r dir; do
                rmdir -- "$dir" 2>/dev/null || true
            done
        if [[ ! -e "$path" ]]; then
            return 0
        fi
        sleep 0.02
    done
    [[ ! -e "$path" ]]
}
