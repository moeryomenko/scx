#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_queue_stress.sh - queue progress and lifetime harness.
#
# The harness loads scx_infinity and runs these phases against a live
# scheduler:
#
#   burn       one CPU-bound worker per CPU
#   sleep      sleepers next to CPU-bound workers, so wakeups contend
#   forkexec   repeated fork and exec, so short-lived tasks enter and exit
#   affinity   workers that narrow their own mask and sample their CPU,
#              an out-of-mask sample is an affinity violation
#   migrate    workers that alternate their affinity between two CPUs
#   yield      sched_yield loops, the yield counter must advance
#   reweight   a worker in a cgroup whose cpu.weight changes at run time
#   yieldto    optional external workload that triggers directed yield
#              (KVM), BLOCKED when no such workload is given
#   exit       SIGINT, clean exit and a disabled state
#
# The harness fails closed. It refuses to run without a disposable VM
# (SCX_INFINITY_VM=1), root and the cgroup files. A missing precondition is
# BLOCKED, never PASS. A lost task, a stale queue entry, a watchdog line or
# an affinity violation is a failure.
#
# Usage:
#   SCX_INFINITY_VM=1 sudo \
#     scheds/experimental/scx_infinity/scripts/infinity_queue_stress.sh \
#     [--duration SEC] [--workers N] [--scheduler PATH] [--out FILE] \
#     [--yield-to-cmd CMD] [--check]
#
# Output: one JSON object per line on stdout. The last line is the summary.
# Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED.

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=infinity_harness_lib.sh
. "$SCRIPT_DIR/infinity_harness_lib.sh"

DURATION=8
WORKERS=0
SCHED_BIN=""
CHECK_ONLY=0
OUT=""
YIELD_TO_CMD=""
SCHED_LOG=""
WORKLOAD=""
CGROUP_PARENT=""
CG_STRESS=""
DMESG_BASELINE=0

usage() {
    cat >&2 <<'EOF'
usage: infinity_queue_stress.sh [--duration SEC] [--workers N]
       [--scheduler PATH] [--out FILE] [--yield-to-cmd CMD] [--check]

  --duration SEC     seconds per phase, default 8
  --workers N        worker count, default one per online CPU
  --scheduler PATH   scx_infinity binary, default SCX_INFINITY_BIN or target/
  --out FILE         also append the JSON Lines records to FILE
  --yield-to-cmd CMD run CMD as the directed-yield source, for example a KVM
                     workload; without it the yield-to check is BLOCKED
  --check            verify preconditions only, start nothing
EOF
}

while (($#)); do
    case "$1" in
        --duration)
            DURATION=${2:?}
            shift
            ;;
        --workers)
            WORKERS=${2:?}
            shift
            ;;
        --scheduler)
            SCHED_BIN=${2:?}
            shift
            ;;
        --out)
            OUT=${2:?}
            shift
            ;;
        --yield-to-cmd)
            YIELD_TO_CMD=${2:?}
            shift
            ;;
        --check)
            CHECK_ONLY=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage
            exit 2
            ;;
    esac
    shift
done

if ! [[ "$DURATION" =~ ^[1-9][0-9]*$ ]]; then
    printf 'bad duration: %s\n' "$DURATION" >&2
    exit 2
fi
if (( WORKERS == 0 )); then
    WORKERS=$(nproc)
fi
if ! [[ "$WORKERS" =~ ^[1-9][0-9]*$ ]]; then
    printf 'bad worker count: %s\n' "$WORKERS" >&2
    exit 2
fi

prepare_workload() {
    local source="$SCRIPT_DIR/infinity_workload.c"
    local cc_log="$HARNESS_TMP/cc.log"

    require_file "$source" || return 1
    WORKLOAD="$HARNESS_TMP/infinity_workload"
    if ! cc -O2 -Wall -Wextra -o "$WORKLOAD" "$source" 2>"$cc_log"; then
        record FAIL workload_build "cc failed: $(tail -n 3 "$cc_log" 2>/dev/null || true)"
        return 1
    fi
    record PASS workload_build "compiled $source"
}

preflight() {
    local missing=0
    local state=""

    require_disposable_vm || missing=1
    require_root || missing=1
    require_cgroup_cpu || missing=1
    require_cmd cc || missing=1
    require_cmd taskset || missing=1
    require_cmd timeout || missing=1
    require_cmd renice || missing=1
    require_dmesg || missing=1

    if [[ -z "$SCHED_BIN" ]]; then
        SCHED_BIN=$(resolve_scheduler || true)
    fi
    if [[ -z "$SCHED_BIN" || ! -x "$SCHED_BIN" ]]; then
        record BLOCKED scheduler "no executable scx_infinity binary; set --scheduler or SCX_INFINITY_BIN"
        missing=1
    else
        record PASS scheduler "$SCHED_BIN"
    fi

    state=$(sched_state)
    if [[ "$state" != "disabled" ]]; then
        record BLOCKED sched_state "/sys/kernel/sched_ext/state is '${state:-missing}', expected 'disabled'"
        missing=1
    else
        record PASS sched_state "disabled"
    fi

    if (( missing == 0 )); then
        prepare_workload || missing=1
    fi
    return "$missing"
}

setup_cgroup() {
    local root=""

    if ! root=$(cgroup2_root); then
        record FAIL cgroup "the cgroup v2 mount disappeared"
        exit 1
    fi
    CGROUP_PARENT="$root/scx-infinity-stress.$$"
    if ! mkdir -- "$CGROUP_PARENT" 2>/dev/null; then
        record FAIL cgroup "cannot create $CGROUP_PARENT"
        exit 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$CGROUP_PARENT") 2>/dev/null || true"
    if ! cgroup_enable_cpu_at "$CGROUP_PARENT"; then
        record FAIL cgroup "cannot enable the cpu controller in $CGROUP_PARENT"
        exit 1
    fi
    if ! CG_STRESS=$(cgroup_create "$CGROUP_PARENT" stress); then
        record FAIL cgroup "cannot create the stress cgroup"
        exit 1
    fi
}

start_one() {
    local -r cpu="$1"
    local -r tag="$2"

    shift 2
    start_worker "$CG_STRESS" "$cpu" "$HARNESS_TMP/${tag}.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
        "$WORKLOAD" "$@"
}

start_any_worker() {
    local -r tag="$1"

    shift
    start_worker "$CG_STRESS" any "$HARNESS_TMP/${tag}.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
        "$WORKLOAD" "$@"
}

start_cpu_workers() {
    local -r mode="$1"
    local i

    for (( i=0; i < WORKERS; i++ )); do
        if ! start_one "$(( i % $(nproc) ))" "${mode}_${i}" "$mode" "$DURATION" >/dev/null; then
            record FAIL "${mode}:worker" "cannot start worker $i"
            return 1
        fi
    done
}

start_affinity_workers() {
    local online=""
    local i

    online=$(cat /sys/devices/system/cpu/online 2>/dev/null || true)
    if [[ -z "$online" ]]; then
        record FAIL "affinity:mask" "the online CPU list is missing"
        return 1
    fi
    for (( i=0; i < WORKERS; i++ )); do
        if ! start_one "$(( i % $(nproc) ))" "affinity_${i}" \
            probe "$DURATION" "$online" >/dev/null; then
            record FAIL "affinity:worker" "cannot start worker $i"
            return 1
        fi
    done
}

check_alive() {
    local -r tag="$1"

    if ! scheduler_alive; then
        record FAIL "$tag:scheduler" "the scheduler exited"
        return 1
    fi
    if [[ "$(sched_state)" != "enabled" ]]; then
        record FAIL "$tag:scheduler" "/sys/kernel/sched_ext/state is not enabled"
        return 1
    fi
}

phase_burn() {
    local head0
    local head1
    local exp0
    local exp1
    local extra

    head0=$(stat_value "$SCHED_LOG" head)
    exp0=$(stat_value "$SCHED_LOG" expiries)
    start_cpu_workers burn || { stop_all_workers; return; }
    if ! join_workers; then
        record FAIL burn "a CPU-bound worker exited non-zero"
        return
    fi
    check_alive burn || return
    head1=$(stat_value "$SCHED_LOG" head)
    exp1=$(stat_value "$SCHED_LOG" expiries)
    extra=$(printf '"head_before":%s,"head_after":%s,"expiries_before":%s,"expiries_after":%s' \
        "$head0" "$head1" "$exp0" "$exp1")
    if (( head1 <= head0 )); then
        record FAIL burn "head_inserts did not advance" "$extra"
        return
    fi
    record PASS burn "$WORKERS CPU-bound workers made progress without a stall" "$extra"
}

phase_sleep() {
    local i
    local head0
    local head1
    local pre0
    local pre1
    local extra

    head0=$(stat_value "$SCHED_LOG" head)
    pre0=$(stat_value "$SCHED_LOG" preemptions)
    for (( i=0; i < WORKERS; i++ )); do
        if ! start_one "$(( i % $(nproc) ))" "sleeper_${i}" sleeper "$DURATION" >/dev/null; then
            record FAIL sleep "cannot start a sleeper"
            stop_all_workers
            return
        fi
    done
    start_cpu_workers burn || { stop_all_workers; return; }
    if ! join_workers; then
        record FAIL sleep "a worker exited non-zero"
        return
    fi
    check_alive sleep || return
    head1=$(stat_value "$SCHED_LOG" head)
    pre1=$(stat_value "$SCHED_LOG" preemptions)
    extra=$(printf '"head_before":%s,"head_after":%s,"preemptions_before":%s,"preemptions_after":%s' \
        "$head0" "$head1" "$pre0" "$pre1")
    if (( head1 <= head0 )); then
        record FAIL sleep "head_inserts did not advance" "$extra"
        return
    fi
    record PASS sleep "$WORKERS sleepers and $WORKERS burners ran" "$extra"
}

phase_forkexec() {
    local count=$(( WORKERS / 2 ))
    local i
    local head0
    local head1
    local extra

    if (( count < 2 )); then
        count=2
    fi
    head0=$(stat_value "$SCHED_LOG" head)
    for (( i=0; i < count; i++ )); do
        if ! start_one "$(( i % $(nproc) ))" "forkexec_${i}" forkexec "$DURATION" >/dev/null; then
            record FAIL forkexec "cannot start a fork workload"
            stop_all_workers
            return
        fi
    done
    if ! join_workers; then
        record FAIL forkexec "a fork workload exited non-zero"
        return
    fi
    check_alive forkexec || return
    head1=$(stat_value "$SCHED_LOG" head)
    extra=$(printf '"forkers":%d,"head_before":%s,"head_after":%s' "$count" "$head0" "$head1")
    if (( head1 <= head0 )); then
        record FAIL forkexec "head_inserts did not advance" "$extra"
        return
    fi
    record PASS forkexec "$count fork and exec loops completed" "$extra"
}

phase_affinity() {
    local i
    local log=""
    local out=""
    local samples=""
    local violations=""
    local total=0
    local bad=0
    local extra

    start_affinity_workers || { stop_all_workers; return; }
    if ! join_workers; then
        record FAIL affinity "an affinity worker exited non-zero"
        return
    fi
    check_alive affinity || return
    for (( i=0; i < WORKERS; i++ )); do
        log="$HARNESS_TMP/affinity_${i}.log"
        out=$(tail -n 1 "$log" 2>/dev/null || true)
        samples=$(printf '%s\n' "$out" | grep -oE 'samples=[0-9]+' | cut -d= -f2)
        violations=$(printf '%s\n' "$out" | grep -oE 'out_of_mask=[0-9]+' | cut -d= -f2)
        if [[ -z "$samples" || -z "$violations" ]]; then
            bad=$((bad + 1))
            continue
        fi
        total=$((total + samples))
        if (( violations > 0 )); then
            bad=$((bad + 1))
        fi
    done
    extra=$(printf '"workers":%d,"samples":%d,"violating_workers":%d' \
        "$WORKERS" "$total" "$bad")
    if (( bad > 0 || total == 0 )); then
        record FAIL affinity "an affinity sample left the allowed CPU set" "$extra"
        return
    fi
    record PASS affinity "$total samples, no affinity violation" "$extra"
}

phase_migrate() {
    local i
    local log=""
    local migrations=0
    local value=0
    local extra

    for (( i=0; i < WORKERS; i++ )); do
        if ! start_any_worker "migrate_${i}" migrate "$DURATION" >/dev/null; then
            record FAIL migrate "cannot start a migration worker"
            stop_all_workers
            return
        fi
    done
    if ! join_workers; then
        record FAIL migrate "a migration worker exited non-zero"
        return
    fi
    check_alive migrate || return
    for (( i=0; i < WORKERS; i++ )); do
        log="$HARNESS_TMP/migrate_${i}.log"
        value=$(grep -oE 'migrations=[0-9]+' "$log" 2>/dev/null | tail -n 1 | cut -d= -f2 || true)
        migrations=$((migrations + ${value:-0}))
    done
    extra=$(printf '"workers":%d,"migrations":%d' "$WORKERS" "$migrations")
    if (( migrations == 0 )); then
        record FAIL migrate "no affinity change completed" "$extra"
        return
    fi
    record PASS migrate "$migrations affinity changes completed" "$extra"
}

phase_yield() {
    local i
    local yields0
    local yields1
    local extra

    yields0=$(stat_value "$SCHED_LOG" yields)
    start_cpu_workers yield || { stop_all_workers; return; }
    if ! join_workers; then
        record FAIL yield "a yield worker exited non-zero"
        return
    fi
    check_alive yield || return
    yields1=$(stat_value "$SCHED_LOG" yields)
    extra=$(printf '"yields_before":%s,"yields_after":%s' "$yields0" "$yields1")
    if (( yields1 <= yields0 )); then
        record FAIL yield "the yield counter did not advance" "$extra"
        return
    fi
    record PASS yield "the scheduler saw $((yields1 - yields0)) yields" "$extra"
}

phase_reweight() {
    local changes0
    local changes1
    local refolds0
    local refolds1
    local pid=""
    local extra

    changes0=$(stat_value "$SCHED_LOG" weight_changes)
    refolds0=$(stat_value "$SCHED_LOG" refolds)
    if ! pid=$(start_worker "$CG_STRESS" 0 "$HARNESS_TMP/reweight_worker.log" \
        "$WORKLOAD" burn "$DURATION"); then
        record FAIL reweight "cannot start the reweight worker"
        return
    fi
    sleep 1
    if ! renice 5 -p "$pid" >/dev/null 2>&1; then
        stop_all_workers
        record FAIL reweight "cannot change the nice value of the worker"
        return
    fi
    sleep 0.5
    if ! renice 0 -p "$pid" >/dev/null 2>&1; then
        stop_all_workers
        record FAIL reweight "cannot restore the nice value of the worker"
        return
    fi
    if ! cgroup_write "$CG_STRESS" cpu.weight 200; then
        stop_all_workers
        record FAIL reweight "cannot write cpu.weight 200"
        return
    fi
    sleep 1
    if ! cgroup_write "$CG_STRESS" cpu.weight 100; then
        stop_all_workers
        record FAIL reweight "cannot write cpu.weight 100"
        return
    fi
    if ! join_workers; then
        record FAIL reweight "the reweight worker exited non-zero"
        return
    fi
    check_alive reweight || return
    changes1=$(stat_value "$SCHED_LOG" weight_changes)
    refolds1=$(stat_value "$SCHED_LOG" refolds)
    extra=$(printf '"weight_changes_before":%s,"weight_changes_after":%s,"refolds_before":%s,"refolds_after":%s' \
        "$changes0" "$changes1" "$refolds0" "$refolds1")
    if (( changes1 <= changes0 )); then
        record FAIL reweight "the task weight change counter did not advance" "$extra"
        return
    fi
    record PASS reweight "a nice change and two live cpu.weight writes were applied" "$extra"
}

phase_yieldto() {
    local before
    local after
    local extra

    if [[ -z "$YIELD_TO_CMD" ]]; then
        record BLOCKED yieldto "no --yield-to-cmd; directed yield is reachable only through KVM in the guest"
        return
    fi
    before=$(stat_value "$SCHED_LOG" yield_to)
    if ! timeout --signal=TERM --kill-after=5s "$((DURATION + 10))s" \
        bash -c "$YIELD_TO_CMD" >"$HARNESS_TMP/yieldto.log" 2>&1; then
        record FAIL yieldto "the directed-yield workload failed"
        return
    fi
    check_alive yieldto || return
    after=$(stat_value "$SCHED_LOG" yield_to)
    extra=$(printf '"yield_to_before":%s,"yield_to_after":%s' "$before" "$after")
    if (( after <= before )); then
        record FAIL yieldto "yield_to_moves did not advance" "$extra"
        return
    fi
    record PASS yieldto "the scheduler moved $((after - before)) yield-to targets" "$extra"
}

phase_exit() {
    local lost=0
    local stale=0
    local reweights0
    local reweights1
    local extra

    lost=$(stat_value "$SCHED_LOG" lost)
    stale=$(stat_value "$SCHED_LOG" stale)
    reweights0=$(stat_value "$SCHED_LOG" reweight)
    stop_scheduler
    if [[ "${HARNESS_SCHED_RC:-1}" -eq 0 ]]; then
        record PASS scheduler_exit "the scheduler exited with status 0"
    else
        record FAIL scheduler_exit "the scheduler exited with status ${HARNESS_SCHED_RC:-unknown}"
    fi
    if [[ "$(sched_state)" == "disabled" ]]; then
        record PASS sched_state_exit "state is disabled"
    else
        record FAIL sched_state_exit "state is '$(sched_state)' after exit"
    fi
    reweights1=$(stat_value "$SCHED_LOG" reweight)
    extra=$(printf '"lost":%s,"stale":%s,"reweight_before":%s,"reweight_after":%s' \
        "$lost" "$stale" "$reweights0" "$reweights1")
    if (( lost == 0 && stale == 0 )); then
        record PASS lost_tasks "lost=0 stale=0" "$extra"
    else
        record FAIL lost_tasks "lost=$lost stale=$stale" "$extra"
    fi
}

teardown() {
    local faults=""

    stop_all_workers
    stop_scheduler
    faults=$(dmesg_new_faults "$DMESG_BASELINE")
    if [[ -z "$faults" ]]; then
        record PASS dmesg "no scheduler fault in dmesg"
    else
        record FAIL dmesg "kernel fault: $(printf '%s' "$faults" | head -n 1)"
    fi
    cgroup_write "$CG_STRESS" cpu.weight 100 2>/dev/null || true
    rmdir -- "$CG_STRESS" "$CGROUP_PARENT" 2>/dev/null || true
    if [[ ! -e "$CG_STRESS" && ! -e "$CGROUP_PARENT" ]]; then
        record PASS cgroup_cleanup "the stress cgroup was removed"
    else
        record FAIL cgroup_cleanup "the stress cgroup remains"
    fi
}

main() {
    harness_init queue_stress
    if [[ -n "$OUT" ]]; then
        HARNESS_JSON_OUT=$OUT
        : >"$OUT"
    fi
    SCHED_LOG="$HARNESS_TMP/scheduler.log"

    if ! preflight; then
        exit 2
    fi
    if (( CHECK_ONLY )); then
        record PASS check_only "preconditions verified; no workload started"
        exit 0
    fi

    setup_cgroup
    DMESG_BASELINE=$(dmesg_lines)
    start_scheduler "$SCHED_BIN" "$SCHED_LOG"
    if ! wait_for_sched_state enabled 10; then
        record FAIL scheduler "state did not become enabled"
        tail -n 5 "$SCHED_LOG" >&2 || true
        exit 1
    fi
    record PASS scheduler "state enabled"
    sleep 1.2

    phase_burn
    phase_sleep
    phase_forkexec
    phase_affinity
    phase_migrate
    phase_yield
    phase_reweight
    phase_yieldto
    phase_exit
    teardown
}

main "$@"
