#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_queue_stress.sh - queue progress, handoff and lifetime harness.
#
# The harness loads scx_infinity and runs these phases against a live
# scheduler:
#
#   burn       one CPU-bound worker per CPU
#   sleep      sleepers next to CPU-bound workers, so wakeups contend;
#              sched_wakeup to sched_switch latency is measured with
#              ftrace and every sleeper must run within 100 ms
#   forkexec   repeated fork and exec, so short-lived tasks enter and exit
#   affinity   workers that narrow their own mask and sample their CPU,
#              an out-of-mask sample is an affinity violation
#   migrate    workers that alternate their affinity between two CPUs
#   yield      sched_yield loops, the yield counter must advance
#   reweight   a worker in a cgroup whose cpu.weight changes at run time
#   parked     a worker throttled by cpu.max, classified separately from
#              a stall, with the bandwidth refill path checked
#   yieldto    optional external workload that triggers directed yield
#              (KVM), BLOCKED when no such workload is given
#   faults     one injected handoff failure per kind, so a refused insert,
#              a refused remove, a refused steal and a lost hold each prove
#              that no task is lost and no ownership is duplicated
#   exit       SIGINT, clean exit and a disabled state
#
# Revision-4 oracles. A continuously runnable worker must advance at least
# once every five seconds. A sleeper must run within 100 ms after its
# wakeup. An internal handoff must resolve within one measured tick.
# A quota-parked task is judged by the bandwidth queue and the refill
# path, not by the five-second progress oracle.
#
# The harness reads these counters from the newest statistics line:
#
#   ticks              one ops.tick call, one service slot
#   handoffs           completed internal handoffs
#   handoff_max_ns     longest handoff resolution, nanoseconds
#   handoff_overdue    handoffs that spanned more than one tick
#   handoff_orphans    tasks left in a handoff state
#   handoff_duplicates tasks owned by two queues at once
#   faults_injected    injected handoff failures
#   cgrp: throttled / cgrp: reenqueued   the quota park and refill path
#
# A missing counter is FAIL for its oracle. It is never PASS.
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
#     [--yield-to-cmd CMD] [--mixed] [--inject KIND[:COUNT]] [--inject-all] \
#     [--check] [--selftest]
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
CG_PARKED=""
DMESG_BASELINE=0
TRACE=0
DSQ_REFUSE=""
MIXED=0
DUMP_DIR=""
SCHED_EXTRA=()
FAULTS=()
MIX_PIDS=()
MIX_KINDS=()
MIX_TAGS=()
TICK_NS=0
SELFTEST=0
PROGRESS_STALLS=0
MIX_MONITOR_HOOK=""
PHASE_START=0
REWEIGHT_STEP=0
REWEIGHT_PID=""
PARK_MID=0
PARK_STEP=0
PARKED_PID=""
PARKED_TICKS0=0
PARKED_TICKS1=0
TH0=0
TH1=0
RE0=0
RE1=0

usage() {
    cat >&2 <<'EOF'
usage: infinity_queue_stress.sh [--duration SEC] [--workers N]
       [--scheduler PATH] [--out FILE] [--yield-to-cmd CMD] [--check]
       [--mixed] [--trace] [--test-dsq-refuse N] [--dump-dir DIR]
       [--inject KIND[:COUNT]] [--inject-all] [--selftest]

  --duration SEC     seconds per phase, or the whole mixed campaign with --mixed
  --workers N        worker count, default one per online CPU
  --scheduler PATH   scx_infinity binary, default SCX_INFINITY_BIN or target/
  --out FILE         also append the JSON Lines records to FILE
  --yield-to-cmd CMD run CMD as the directed-yield source, for example a KVM
                     workload; without it the yield-to check is BLOCKED
  --mixed            run every workload class at once for --duration instead
                     of the serial phases: the ten-minute stall campaign
  --trace            load the scheduler with its diagnostic transition trace
  --test-dsq-refuse N
                     arm N controlled local DSQ insert refusals, so the
                     requeue fallback runs without a kernel refusal
  --inject KIND[:COUNT]
                     arm COUNT (default 1) injected handoff failures of KIND:
                     dsq, dest-insert, source-remove, steal or hold. The
                     scheduler option is --test-handoff-fail KIND:COUNT.
  --inject-all       arm four failures of every handoff kind: the final-build
                     campaign gate of specification section 7.3
  --dump-dir DIR     copy the scheduler log, dmesg and every worker log to DIR
  --check            verify preconditions only, start nothing
  --selftest         test the harness helpers, no root and no VM
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
        --mixed)
            MIXED=1
            ;;
        --trace)
            TRACE=1
            ;;
        --test-dsq-refuse)
            DSQ_REFUSE=${2:?}
            shift
            ;;
        --dump-dir)
            DUMP_DIR=${2:?}
            shift
            ;;
        --inject)
            if ! fault_spec_valid "${2:?}"; then
                printf 'bad injection kind: %s\n' "$2" >&2
                exit 2
            fi
            FAULTS+=("$2")
            shift
            ;;
        --inject-all)
            FAULTS+=(dsq:4 dest-insert:4 source-remove:4 steal:4 hold:4)
            ;;
        --selftest)
            SELFTEST=1
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
    if ! CG_PARKED=$(cgroup_create "$CGROUP_PARENT" parked); then
        record FAIL cgroup "cannot create the parked cgroup"
        exit 1
    fi
    cleanup_push 'stop_all_workers'
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

# A dead scheduler makes every later phase meaningless, because the load
# then runs under the fair class. Stop instead of recording CFS results.
abort_if_dead() {
    if ! scheduler_alive || [[ "$(sched_state)" != "enabled" ]]; then
        record FAIL run_aborted \
            "the scheduler exited or was disabled; the remaining phases did not run"
        exit 1
    fi
}

#
# Start one mixed-campaign worker and remember its tag, its progress class
# and its PID. Kinds: burn, sleeper, forkexec, migrate, probe, yield,
# parked. The progress oracle skips sleeper and parked.
start_mix() {
    local -r tag="$1"
    local -r kind="$2"
    local -r cpu="$3"

    shift 3
    if ! start_worker "$CG_STRESS" "$cpu" "$HARNESS_TMP/${tag}.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 30))s" \
        "$WORKLOAD" "$@" >/dev/null; then
        return 1
    fi
    MIX_PIDS+=("$HARNESS_LAST_PID")
    MIX_KINDS+=("$kind")
    MIX_TAGS+=("$tag")
}

#
# The campaign actions that must land while the workers run: a nice
# change and two live cpu.weight writes, then the quota lift for the
# parked worker. monitor_mixed calls this once a second.
mixed_actions() {
    local -r now="$1"
    local elapsed=$((now - PHASE_START))

    if (( elapsed >= 2 )) && (( REWEIGHT_STEP == 0 )); then
        REWEIGHT_STEP=1
        if [[ -n "$REWEIGHT_PID" ]]; then
            renice 5 -p "$REWEIGHT_PID" >/dev/null 2>&1 || true
        fi
        cgroup_write "$CG_STRESS" cpu.weight 200 || true
    fi
    if (( elapsed >= 3 )) && (( REWEIGHT_STEP == 1 )); then
        REWEIGHT_STEP=2
        if [[ -n "$REWEIGHT_PID" ]]; then
            renice 0 -p "$REWEIGHT_PID" >/dev/null 2>&1 || true
        fi
        cgroup_write "$CG_STRESS" cpu.weight 100 || true
    fi
    if (( elapsed >= PARK_MID )) && (( PARK_STEP == 0 )); then
        PARK_STEP=1
        PARKED_TICKS0=$(proc_tree_cpu_ticks "$PARKED_PID" 2>/dev/null || echo 0)
        cgroup_write "$CG_PARKED" cpu.max "max 100000" || true
    fi
    if (( elapsed >= PARK_MID + 2 )) && (( PARK_STEP == 1 )); then
        PARK_STEP=2
        PARKED_TICKS1=$(proc_tree_cpu_ticks "$PARKED_PID" 2>/dev/null || echo 0)
        TH1=$(stat_value "$SCHED_LOG" throttled)
        RE1=$(stat_value "$SCHED_LOG" reenqueued)
    fi
}

#
# Watch every mixed worker while it runs. A worker advances when the CPU
# time of its process subtree grows. A continuously runnable worker that
# does not advance for five seconds is a FAIL. A sleeper is judged by the
# wakeup latency, a parked task by the bandwidth counters.
monitor_mixed() {
    local -r max_seconds="$1"
    local -A last_ticks=()
    local -A last_change=()
    local -A reported=()
    local start=0
    local now=0
    local pid=""
    local kind=""
    local state=""
    local ticks=0
    local i
    local alive=0
    local stalled=0
    local gap=0

    start=$(date +%s)
    while :; do
        now=$(date +%s)
        if [[ -n "${MIX_MONITOR_HOOK:-}" ]]; then
            "$MIX_MONITOR_HOOK" "$now"
        fi
        alive=0
        for i in "${!MIX_PIDS[@]}"; do
            pid=${MIX_PIDS[i]}
            kind=${MIX_KINDS[i]}
            if ! kill -0 "$pid" 2>/dev/null; then
                continue
            fi
            state=$(proc_state "$pid" 2>/dev/null || true)
            if [[ -z "$state" || "$state" == "Z" ]]; then
                continue
            fi
            alive=1
            ticks=$(proc_tree_cpu_ticks "$pid" 2>/dev/null || echo 0)
            if [[ -z "${last_ticks[$pid]:-}" ]]; then
                last_ticks[$pid]=$ticks
                last_change[$pid]=$now
                continue
            fi
            if (( ticks > last_ticks[$pid] )); then
                last_ticks[$pid]=$ticks
                last_change[$pid]=$now
            fi
            if [[ "$kind" == "sleeper" || "$kind" == "parked" ]]; then
                continue
            fi
            gap=$((now - last_change[$pid]))
            if (( gap >= 5 )) && [[ -z "${reported[$pid]:-}" ]]; then
                reported[$pid]=1
                stalled=$((stalled + 1))
                record FAIL "progress:$pid" \
                    "$kind worker $pid did not advance for $gap s" \
                    "$(printf '"pid":%s,"kind":"%s","gap_s":%d' \
                        "$pid" "$kind" "$gap")"
            fi
        done
        if (( alive == 0 )); then
            break
        fi
        if (( now - start >= max_seconds )); then
            break
        fi
        sleep 1
    done
    PROGRESS_STALLS=$((PROGRESS_STALLS + stalled))
}

#
# Measure one tick. A pinned busy worker makes ops.tick fire; the
# scheduler exports the count. The rate is the measured tick.
phase_tick() {
    local pid=""
    local ticks0=0
    local ticks1=0

    if ! stat_key_present "$SCHED_LOG" ticks; then
        record BLOCKED tick_source \
            "the statistics line has no 'ticks' counter; the one-tick handoff deadline cannot be measured"
        TICK_NS=0
        return
    fi
    if ! start_worker "$CG_STRESS" 0 "$HARNESS_TMP/tick_burn.log" \
        "$WORKLOAD" burn 5 >/dev/null; then
        record BLOCKED tick_source "cannot start the tick measurement worker"
        TICK_NS=0
        return
    fi
    pid=$HARNESS_LAST_PID
    sleep 0.5
    ticks0=$(stat_value "$SCHED_LOG" ticks)
    sleep 2
    ticks1=$(stat_value "$SCHED_LOG" ticks)
    stop_worker "$pid"
    HARNESS_WORKER_PIDS=()
    if (( ticks1 <= ticks0 )); then
        record BLOCKED tick_source \
            "the tick counter did not advance ($ticks0 to $ticks1) under a pinned busy task"
        TICK_NS=0
        return
    fi
    TICK_NS=$(tick_ns_from_seconds 2 "$((ticks1 - ticks0))")
    record PASS tick_source "one tick is $TICK_NS ns over a 2 s window"
}

#
# The quota-parked path. The worker is throttled by cpu.max, so the
# five-second progress oracle does not apply. The park counter must rise,
# and the task must run again after the quota is lifted: that is the
# bandwidth refill path.
phase_parked() {
    local peer_pid=""
    local parked_pid=""
    local th0=0
    local th1=0
    local re0=0
    local re1=0
    local ticks0=0
    local ticks1=0
    local extra=""

    if ! cgroup_write "$CG_PARKED" cpu.max "1000 100000"; then
        record FAIL parked "cannot set cpu.max on the parked cgroup"
        return
    fi
    cgroup_write "$CG_PARKED" cpu.max.burst 0 || true
    if ! start_worker "$CG_STRESS" 0 "$HARNESS_TMP/parked_peer.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 25))s" \
        "$WORKLOAD" burn "$((DURATION + 10))" >/dev/null; then
        record FAIL parked "cannot start the contention worker"
        return
    fi
    peer_pid=$HARNESS_LAST_PID
    if ! start_worker "$CG_PARKED" 0 "$HARNESS_TMP/parked_worker.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 25))s" \
        "$WORKLOAD" burn "$((DURATION + 10))" >/dev/null; then
        stop_worker "$peer_pid"
        record FAIL parked "cannot start the throttled worker"
        return
    fi
    parked_pid=$HARNESS_LAST_PID
    sleep 1
    th0=$(stat_value "$SCHED_LOG" throttled)
    re0=$(stat_value "$SCHED_LOG" reenqueued)
    sleep "$DURATION"
    th1=$(stat_value "$SCHED_LOG" throttled)
    re1=$(stat_value "$SCHED_LOG" reenqueued)
    ticks0=$(proc_tree_cpu_ticks "$parked_pid")
    if ! cgroup_write "$CG_PARKED" cpu.max "max 100000"; then
        stop_worker "$peer_pid"
        stop_worker "$parked_pid"
        record FAIL parked "cannot lift the quota for the refill check"
        return
    fi
    sleep 1.5
    ticks1=$(proc_tree_cpu_ticks "$parked_pid")
    stop_worker "$peer_pid"
    stop_worker "$parked_pid"
    HARNESS_WORKER_PIDS=()
    log="$HARNESS_TMP/parked_worker.log"
    extra=$(printf '"throttled_before":%s,"throttled_after":%s,"reenqueued_before":%s,"reenqueued_after":%s,"ticks_before":%s,"ticks_after":%s,"class":"parked"' \
        "$th0" "$th1" "$re0" "$re1" "$ticks0" "$ticks1")
    check_alive parked || return
    if (( th1 <= th0 )); then
        record FAIL parked \
            "the throttled worker was not parked: the throttle counter did not rise" "$extra"
        return
    fi
    if (( re1 < re0 )); then
        record FAIL parked "the bandwidth reenqueue counter went backwards" "$extra"
        return
    fi
    if (( ticks1 <= ticks0 )); then
        record FAIL parked \
            "the parked worker did not run after the quota was lifted" "$extra"
        return
    fi
    record PASS parked \
        "the worker was parked $((th1 - th0)) times and ran again after refill" "$extra"
}

#
# Fault injection. Every kind loads the scheduler again with one bounded
# injection and runs a short mixed load. The case passes only when the
# injection landed, every worker finished, no task is lost, no task is in
# a handoff state and the longest handoff is within one tick.
run_fault_case() {
    local -r spec="$1"
    local kind=""
    local count=1
    local faults0=0
    local faults1=0
    local lost0=0
    local lost1=0
    local stale0=0
    local stale1=0
    local handoffs=0
    local handoff_max=0
    local overdue=0
    local orphans=0
    local duplicates=0
    local i=0
    local cpu=0
    local seconds=0
    local extra=""
    local ok=1

    kind=$(fault_spec_kind "$spec")
    count=$(fault_spec_count "$spec")
    stop_scheduler
    start_scheduler "$SCHED_BIN" "$SCHED_LOG" "${SCHED_EXTRA[@]}" \
        --test-handoff-fail "${kind}:${count}"
    if ! wait_for_sched_state enabled 10; then
        record FAIL "fault:$kind" "the scheduler did not enable with ${kind}:${count}"
        return
    fi
    if ! require_scheduler_identity; then
        record BLOCKED "fault:$kind" \
            "the loaded scheduler is not scx_infinity, so the injection is not attributed"
        stop_scheduler
        return
    fi
    if ! require_stat_keys "$SCHED_LOG" "fault:$kind" \
        handoffs handoff_max_ns handoff_overdue handoff_orphans \
        handoff_duplicates faults_injected; then
        ok=0
    fi
    faults0=$(stat_value "$SCHED_LOG" faults_injected)
    lost0=$(stat_value "$SCHED_LOG" lost)
    stale0=$(stat_value "$SCHED_LOG" stale)
    MIX_PIDS=()
    MIX_KINDS=()
    MIX_TAGS=()
    seconds=$(( DURATION < 6 ? DURATION : 6 ))
    for (( i = 0; i < WORKERS; i++ )); do
        cpu=$(( i % $(nproc) ))
        start_mix "fault_${kind}_burn_${i}" burn "$cpu" burn "$seconds" >/dev/null ||
            { record FAIL "fault:$kind" "cannot start a burn worker"; ok=0; }
        start_mix "fault_${kind}_mig_${i}" migrate any migrate "$seconds" >/dev/null ||
            { record FAIL "fault:$kind" "cannot start a migrate worker"; ok=0; }
    done
    start_mix "fault_${kind}_fork" forkexec 0 forkexec "$seconds" >/dev/null ||
        { record FAIL "fault:$kind" "cannot start a fork worker"; ok=0; }
    start_mix "fault_${kind}_sleep" sleeper 0 sleeper "$seconds" >/dev/null ||
        { record FAIL "fault:$kind" "cannot start a sleeper"; ok=0; }
    monitor_mixed "$((seconds + 10))"
    if ! join_workers; then
        record FAIL "fault:$kind" "a worker exited non-zero"
        ok=0
    fi
    check_alive "fault:$kind" || ok=0
    faults1=$(stat_value "$SCHED_LOG" faults_injected)
    lost1=$(stat_value "$SCHED_LOG" lost)
    stale1=$(stat_value "$SCHED_LOG" stale)
    handoffs=$(stat_value "$SCHED_LOG" handoffs)
    handoff_max=$(stat_value "$SCHED_LOG" handoff_max_ns)
    overdue=$(stat_value "$SCHED_LOG" handoff_overdue)
    orphans=$(stat_value "$SCHED_LOG" handoff_orphans)
    duplicates=$(stat_value "$SCHED_LOG" handoff_duplicates)
    extra=$(printf '"kind":"%s","requested":%s,"injected":%s,"handoffs":%s,"handoff_max_ns":%s,"tick_ns":%s,"overdue":%s,"orphans":%s,"duplicates":%s,"lost_before":%s,"lost_after":%s,"stale_before":%s,"stale_after":%s' \
        "$kind" "$count" "$((faults1 - faults0))" "$handoffs" "$handoff_max" \
        "$TICK_NS" "$overdue" "$orphans" "$duplicates" \
        "$lost0" "$lost1" "$stale0" "$stale1")
    if (( faults1 - faults0 < count )); then
        record FAIL "fault:$kind" \
            "the scheduler reported $((faults1 - faults0)) of $count injected failures" "$extra"
    elif (( lost1 != lost0 || stale1 != stale0 )); then
        record FAIL "fault:$kind" \
            "lost or stale state changed around the injection" "$extra"
    elif (( overdue != 0 || orphans != 0 || duplicates != 0 )); then
        record FAIL "fault:$kind" \
            "a handoff stayed open, was duplicated or spanned more than one tick" "$extra"
    elif (( TICK_NS > 0 && handoff_max > TICK_NS )); then
        record FAIL "fault:$kind" \
            "the longest handoff ${handoff_max} ns exceeds one measured tick ${TICK_NS} ns" "$extra"
    elif (( ok == 0 )); then
        record FAIL "fault:$kind" "a worker or counter check failed" "$extra"
    else
        record PASS "fault:$kind" \
            "$((faults1 - faults0)) injected failures, no lost or duplicated task" "$extra"
    fi
    stop_scheduler
    if [[ "${HARNESS_SCHED_RC:-1}" -eq 0 ]]; then
        record PASS "fault:$kind:exit" "the scheduler exited with status 0"
    else
        record FAIL "fault:$kind:exit" \
            "the scheduler exited with status ${HARNESS_SCHED_RC:-unknown}"
    fi
    if [[ "$(sched_state)" != "disabled" ]]; then
        record FAIL "fault:$kind:state" "state is '$(sched_state)' after exit"
    fi
}

phase_faults() {
    local spec=""

    if (( ${#FAULTS[@]} == 0 )); then
        record BLOCKED fault_injection \
            "no --inject given; the revision-4 handoff fault gate did not run"
        return
    fi
    for spec in "${FAULTS[@]}"; do
        run_fault_case "$spec"
    done
}

# Unit tests for the pure helpers. No root, no scheduler and no VM.
run_helper_selftest() {
    local trace="$HARNESS_TMP/wake-trace.txt"
    local log="$HARNESS_TMP/stats.log"
    local summary=""
    local value=""
    local missing=0
    local pid=""
    local state=""

    check_equal() {
        local -r name="$1"
        local -r expected="$2"
        local -r actual="$3"

        if [[ "$expected" == "$actual" ]]; then
            record PASS "$name" "expected $expected"
        else
            record FAIL "$name" "expected '$expected', got '$actual'"
            missing=$((missing + 1))
        fi
    }

    check_true() {
        local -r name="$1"

        shift
        if "$@"; then
            record PASS "$name" "true"
        else
            record FAIL "$name" "false"
            missing=$((missing + 1))
        fi
    }

    check_false() {
        local -r name="$1"

        shift
        if "$@"; then
            record FAIL "$name" "true"
            missing=$((missing + 1))
        else
            record PASS "$name" "false"
        fi
    }

    check_true "identity_matches accepts scx_infinity" \
        identity_matches scx_infinity scx_infinity
    check_true "identity_matches accepts the version suffix" \
        identity_matches scx_infinity_1.1.4_x86_64_unknown_linux_gnu_debug scx_infinity
    check_false "identity_matches rejects infinity" \
        identity_matches infinity_1.1.4_x86_64_unknown_linux_gnu_debug scx_infinity
    check_false "identity_matches rejects an empty name" \
        identity_matches "" scx_infinity
    check_equal fault_spec_kind_dest "dest-insert" \
        "$(fault_spec_kind dest-insert:4)"
    check_equal fault_spec_count_dest "4" "$(fault_spec_count dest-insert:4)"
    check_equal fault_spec_count_default "1" "$(fault_spec_count steal)"
    check_true "fault_spec_valid accepts all kinds" \
        fault_spec_valid hold:3
    check_false "fault_spec_valid rejects an unknown kind" \
        fault_spec_valid bogus:1
    check_false "fault_spec_valid rejects a zero count" \
        fault_spec_valid steal:0
    check_equal tick_ns_math "1000000" "$(tick_ns_from_seconds 2 2000)"
    check_equal tick_ns_zero "0" "$(tick_ns_from_seconds 2 0)"
    check_equal summary_field_match "2" "$(summary_field 'matched=2 unmatched=1' matched)"
    check_equal summary_field_missing "" "$(summary_field 'matched=2' absent)"

    cat >"$log" <<'EOF'
2026-10-20 10:00:00 INFO inserts: head=1 tail=0 ticks=42 handoffs=3 handoff_max_ns=900000
EOF
    check_true "stat_key_present finds ticks" stat_key_present "$log" ticks
    check_false "stat_key_present rejects a missing key" \
        stat_key_present "$log" handoff_dup

    cat >"$trace" <<'EOF'
            sleep-1 [000] d..2. 1000.000000: sched_wakeup: comm=infinity_worklo pid=200 prio=120 target_cpu=000
            sleep-1 [000] d..2. 1000.010000: sched_switch: prev_comm=sleep prev_pid=200 prev_prio=120 prev_state=S ==> next_comm=infinity_worklo next_pid=200 next_prio=120
            sleep-1 [000] d..2. 1001.000000: sched_wakeup: comm=infinity_worklo pid=200 prio=120 target_cpu=000
            sleep-1 [000] d..2. 1001.050000: sched_switch: prev_comm=sleep prev_pid=200 prev_prio=120 prev_state=S ==> next_comm=infinity_worklo next_pid=200 next_prio=120
            sleep-1 [000] d..2. 1002.000000: sched_wakeup: comm=infinity_worklo pid=201 prio=120 target_cpu=000
EOF
    summary=$(wake_latency_summary "$trace" 200 201)
    check_equal wake_latency_matched "2" "$(summary_field "$summary" matched)"
    check_equal wake_latency_unmatched "1" "$(summary_field "$summary" unmatched)"
    check_equal wake_latency_max "50000" "$(summary_field "$summary" max_us)"
    check_equal wake_latency_p99 "50000" "$(summary_field "$summary" p99_us)"
    check_equal trace_lost_none "0" "$(trace_lost_events "$trace")"
    printf 'CPU:3 [LOST 7 EVENTS]\n' >"$HARNESS_TMP/lost.txt"
    check_equal trace_lost_count "7" "$(trace_lost_events "$HARNESS_TMP/lost.txt")"

    pid=$$
    state=$(proc_state "$pid" 2>/dev/null || true)
    check_true "proc_state reads the current process" test -n "$state"
    value=$(proc_cpu_ticks "$pid" 2>/dev/null || true)
    check_true "proc_cpu_ticks prints a number" \
        awk -v v="$value" 'BEGIN { exit !(v ~ /^[0-9]+$/) }'
    value=$(proc_tree_pids "$pid")
    if printf '%s\n' "$value" | grep -qx "$pid"; then
        record PASS "proc_tree_pids includes the root" "$pid"
    else
        record FAIL "proc_tree_pids includes the root" "root $pid missing"
        missing=$((missing + 1))
    fi
    value=$(cpu_idle_percent 0 40)
    check_true "cpu_idle_percent prints a percentage" \
        awk -v v="$value" 'BEGIN { exit !(v >= 0 && v <= 100) }'
    return 0
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
    local trace_file="$HARNESS_TMP/sleep-trace.txt"
    local wake_window=0
    local wake_summary=""
    local matched=0
    local unmatched=0
    local max_us=0
    local p99_us=0
    local per_worker=""
    local lost=0
    local workers=0
    local pid_list=""
    local pid=""
    local comm=""
    local comm_pid=""
    local pair=""
    local value=""
    local -a sleeper_pids=()
    local -a pairs=()
    local wake_blocked=0
    local trace_started=0
    local attempt=0

    head0=$(stat_value "$SCHED_LOG" head)
    pre0=$(stat_value "$SCHED_LOG" preemptions)
    for (( i=0; i < WORKERS; i++ )); do
        if ! start_one "$(( i % $(nproc) ))" "sleeper_${i}" sleeper "$DURATION" >/dev/null; then
            record FAIL sleep "cannot start a sleeper"
            stop_all_workers
            return
        fi
    done
    # Start the trace before the burners and resolve the sleeper PIDs at
    # once: under load the sleepers can finish before a slow setup scan
    # reaches them, which would leave the latency window empty.
    if require_tracefs; then
        if wake_trace_start; then
            trace_started=1
        else
            record BLOCKED sleep:wake_latency \
                "cannot enable the sched_wakeup and sched_switch events"
            wake_blocked=1
        fi
    else
        wake_blocked=1
    fi
    for (( attempt = 0; attempt < 10; attempt++ )); do
        sleeper_pids=()
        for (( i=0; i < WORKERS; i++ )); do
            pid=${HARNESS_WORKER_PIDS[i]:-}
            [[ -n "$pid" ]] || continue
            for comm_pid in $(proc_tree_pids "$pid"); do
                comm=$(proc_comm "$comm_pid" 2>/dev/null || true)
                if [[ "$comm" == "infinity_worklo"* ]]; then
                    sleeper_pids+=("$comm_pid")
                fi
            done
        done
        if (( ${#sleeper_pids[@]} >= WORKERS )); then
            break
        fi
        sleep 0.1
    done
    pid_list="${sleeper_pids[*]}"
    if [[ -z "$pid_list" ]]; then
        record BLOCKED sleep:wake_latency "no sleeper workload process was found"
        wake_blocked=1
    fi
    start_cpu_workers burn || { stop_all_workers; return; }
    if (( trace_started )); then
        wake_window=$(( DURATION < 5 ? DURATION : 5 ))
        sleep "$wake_window"
        if ! wake_trace_stop "$trace_file"; then
            record BLOCKED sleep:wake_latency "cannot read the wake trace"
            wake_blocked=1
        fi
    fi

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

    if (( wake_blocked )); then
        return
    fi
    lost=$(trace_lost_events "$trace_file")
    if (( lost > 0 )); then
        record FAIL sleep:wake_latency \
            "the trace ring lost $lost events; the latency evidence is incomplete"
        return
    fi
    # shellcheck disable=SC2086
    wake_summary=$(wake_latency_summary "$trace_file" $pid_list)
    matched=$(summary_field "$wake_summary" matched)
    unmatched=$(summary_field "$wake_summary" unmatched)
    max_us=$(summary_field "$wake_summary" max_us)
    p99_us=$(summary_field "$wake_summary" p99_us)
    per_worker=$(summary_field "$wake_summary" per_worker)
    extra=$(printf '"window_s":%s,"sleepers":%s,"matched":%s,"unmatched":%s,"max_us":%s,"p99_us":%s,"per_worker":"%s"' \
        "$wake_window" "${#sleeper_pids[@]}" "${matched:-0}" "${unmatched:-0}" \
        "${max_us:-0}" "${p99_us:-0}" "$per_worker")
    if [[ "${matched:-0}" == "0" ]]; then
        record FAIL sleep:wake_latency "no sleeper wakeup latency was observed" "$extra"
        return
    fi
    workers=0
    value=""
    IFS=',' read -ra pairs <<<"$per_worker"
    for pair in "${pairs[@]}"; do
        [[ -n "$pair" ]] || continue
        workers=$((workers + 1))
        value=${pair#*:}
        if ! num_in_range "$value" 0 100000; then
            record FAIL sleep:wake_latency \
                "sleeper ${pair%%:*} waited $value us, over the 100 ms limit" "$extra"
            return
        fi
    done
    if (( workers < WORKERS || ${#sleeper_pids[@]} < WORKERS )); then
        record FAIL sleep:wake_latency \
            "only $workers of $WORKERS sleepers produced a latency sample (${#sleeper_pids[@]} resolved)" "$extra"
        return
    fi
    record PASS sleep:wake_latency \
        "$workers sleepers ran within $max_us us of their wakeup, p99 $p99_us us" "$extra"
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
    if ! start_worker "$CG_STRESS" 0 "$HARNESS_TMP/reweight_worker.log" \
        "$WORKLOAD" burn "$DURATION" >/dev/null; then
        record FAIL reweight "cannot start the reweight worker"
        return
    fi
    pid=$HARNESS_LAST_PID
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

#
# The ten-minute stall campaign. Every workload class runs at once, a nice
# change and two live cpu.weight writes land under load, and every worker
# must report that it ran. This is the mixed load that produced the host
# stall; the serial phases are kept for the narrower checks.

phase_mixed() {
    local -a tags=()
    local online=""
    local i count
    local head0 head1 tail0 tail1 exp0 exp1 yields0 yields1
    local changes0 changes1 refolds0 refolds1
    local requeues0 requeues1 lost0 stale0
    local handoffs0 handoffs1 handoff_max=0 overdue=0 orphans=0 duplicates=0
    local bad=0 progress=0 value=""
    local stalls0=0
    local parked_log=""

    online=$(cat /sys/devices/system/cpu/online 2>/dev/null || true)
    if [[ -z "$online" ]]; then
        record FAIL "mixed:mask" "the online CPU list is missing"
        return
    fi

    head0=$(stat_value "$SCHED_LOG" head)
    tail0=$(stat_value "$SCHED_LOG" tail)
    exp0=$(stat_value "$SCHED_LOG" expiries)
    yields0=$(stat_value "$SCHED_LOG" yields)
    changes0=$(stat_value "$SCHED_LOG" weight_changes)
    refolds0=$(stat_value "$SCHED_LOG" refolds)
    requeues0=$(stat_value "$SCHED_LOG" requeues)
    lost0=$(stat_value "$SCHED_LOG" lost)
    stale0=$(stat_value "$SCHED_LOG" stale)
    handoffs0=$(stat_value "$SCHED_LOG" handoffs)
    stalls0=$PROGRESS_STALLS

    tags=()
    MIX_PIDS=()
    MIX_KINDS=()
    MIX_TAGS=()

    for (( i=0; i < WORKERS; i++ )); do
        tags+=("mix_burn_${i}")
        if ! start_mix "mix_burn_${i}" burn "$(( i % $(nproc) ))" \
            burn "$DURATION" >/dev/null; then
            record FAIL "mixed:burn" "cannot start burn worker $i"
            stop_all_workers
            return
        fi
        tags+=("mix_sleeper_${i}")
        if ! start_mix "mix_sleeper_${i}" sleeper "$(( i % $(nproc) ))" \
            sleeper "$DURATION" >/dev/null; then
            record FAIL "mixed:sleeper" "cannot start sleeper $i"
            stop_all_workers
            return
        fi
        tags+=("mix_migrate_${i}")
        if ! start_mix "mix_migrate_${i}" migrate any migrate "$DURATION" >/dev/null; then
            record FAIL "mixed:migrate" "cannot start migrate worker $i"
            stop_all_workers
            return
        fi
        tags+=("mix_probe_${i}")
        if ! start_mix "mix_probe_${i}" probe "$(( i % $(nproc) ))" \
            probe "$DURATION" "$online" >/dev/null; then
            record FAIL "mixed:affinity" "cannot start affinity worker $i"
            stop_all_workers
            return
        fi
    done

    count=$(( WORKERS / 2 ))
    if (( count < 2 )); then
        count=2
    fi
    for (( i=0; i < count; i++ )); do
        tags+=("mix_forkexec_${i}")
        if ! start_mix "mix_forkexec_${i}" forkexec "$(( i % $(nproc) ))" \
            forkexec "$DURATION" >/dev/null; then
            record FAIL "mixed:forkexec" "cannot start fork workload $i"
            stop_all_workers
            return
        fi
        tags+=("mix_yield_${i}")
        if ! start_mix "mix_yield_${i}" yield "$(( i % $(nproc) ))" \
            yield "$DURATION" >/dev/null; then
            record FAIL "mixed:yield" "cannot start yield worker $i"
            stop_all_workers
            return
        fi
    done

    #
    # The quota-parked worker. It is classified as parked, not as a
    # stalled continuously runnable worker, and the quota is lifted half
    # way through so the bandwidth refill path runs.
    cgroup_write "$CG_PARKED" cpu.max "1000 100000" || true
    cgroup_write "$CG_PARKED" cpu.max.burst 0 || true
    if ! start_worker "$CG_PARKED" 0 "$HARNESS_TMP/mix_parked.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 30))s" \
        "$WORKLOAD" burn "$DURATION" >/dev/null; then
        record FAIL "mixed:parked" "cannot start the parked worker"
        stop_all_workers
        return
    fi
    tags+=("mix_parked")
    MIX_PIDS+=("$HARNESS_LAST_PID")
    MIX_KINDS+=(parked)
    MIX_TAGS+=("mix_parked")
    parked_log="$HARNESS_TMP/mix_parked.log"
    sleep 0.5
    TH0=$(stat_value "$SCHED_LOG" throttled)
    RE0=$(stat_value "$SCHED_LOG" reenqueued)
    PARKED_PID=$HARNESS_LAST_PID
    PARKED_TICKS0=0
    PARKED_TICKS1=0
    TH1=$TH0
    RE1=$RE0
    PARK_MID=$(( DURATION / 2 ))
    if (( PARK_MID < 4 )); then
        PARK_MID=4
    fi
    PARK_STEP=0
    REWEIGHT_STEP=0
    REWEIGHT_PID=$HARNESS_LAST_PID
    PHASE_START=$(date +%s)
    MIX_MONITOR_HOOK=mixed_actions
    monitor_mixed "$((DURATION + 30))"
    MIX_MONITOR_HOOK=""

    if ! join_workers; then
        record FAIL mixed "a mixed-load worker exited non-zero"
        return
    fi
    check_alive mixed || return

    for i in "${tags[@]}"; do
        value=$(grep -oE 'cpu_ms=[0-9]+' "$HARNESS_TMP/${i}.log" 2>/dev/null |
            tail -n 1 | cut -d= -f2 || true)
        if grep -q 'done=1' "$HARNESS_TMP/${i}.log" 2>/dev/null; then
            progress=$((progress + 1))
        else
            bad=$((bad + 1))
        fi
        if [[ -n "$value" ]] && (( value <= 0 )); then
            bad=$((bad + 1))
        fi
    done
    bad=$((bad + PROGRESS_STALLS - stalls0))

    head1=$(stat_value "$SCHED_LOG" head)
    tail1=$(stat_value "$SCHED_LOG" tail)
    exp1=$(stat_value "$SCHED_LOG" expiries)
    yields1=$(stat_value "$SCHED_LOG" yields)
    changes1=$(stat_value "$SCHED_LOG" weight_changes)
    refolds1=$(stat_value "$SCHED_LOG" refolds)
    requeues1=$(stat_value "$SCHED_LOG" requeues)
    handoffs1=$(stat_value "$SCHED_LOG" handoffs)
    handoff_max=$(stat_value "$SCHED_LOG" handoff_max_ns)
    overdue=$(stat_value "$SCHED_LOG" handoff_overdue)
    orphans=$(stat_value "$SCHED_LOG" handoff_orphans)
    duplicates=$(stat_value "$SCHED_LOG" handoff_duplicates)
    lost0=$(( $(stat_value "$SCHED_LOG" lost) - lost0 ))
    stale0=$(( $(stat_value "$SCHED_LOG" stale) - stale0 ))

    value=$(printf '"workers":%d,"progress":%d,"bad_workers":%d,"head_before":%s,"head_after":%s,"tail_before":%s,"tail_after":%s,"expiries_before":%s,"expiries_after":%s,"yields_before":%s,"yields_after":%s,"weight_changes_before":%s,"weight_changes_after":%s,"refolds_before":%s,"refolds_after":%s,"requeues_before":%s,"requeues_after":%s,"lost_delta":%s,"stale_delta":%s,"handoffs_before":%s,"handoffs_after":%s,"handoff_max_ns":%s,"tick_ns":%s,"handoff_overdue":%s,"handoff_orphans":%s,"handoff_duplicates":%s,"park_throttled_before":%s,"park_throttled_after":%s,"park_reenqueued_before":%s,"park_reenqueued_after":%s,"park_ticks_before":%s,"park_ticks_after":%s,"progress_stalls":%s' \
        "${#tags[@]}" "$progress" "$bad" "$head0" "$head1" "$tail0" "$tail1" \
        "$exp0" "$exp1" "$yields0" "$yields1" "$changes0" "$changes1" \
        "$refolds0" "$refolds1" "$requeues0" "$requeues1" "$lost0" "$stale0" \
        "$handoffs0" "$handoffs1" "$handoff_max" "$TICK_NS" "$overdue" \
        "$orphans" "$duplicates" "$TH0" "$TH1" "$RE0" "$RE1" \
        "$PARKED_TICKS0" "$PARKED_TICKS1" "$((PROGRESS_STALLS - stalls0))")

    if (( bad > 0 || progress != ${#tags[@]} )); then
        record FAIL mixed "a mixed-load worker did not report progress" "$value"
        return
    fi
    if (( head1 <= head0 )); then
        record FAIL mixed "head_inserts did not advance" "$value"
        return
    fi
    if (( exp1 <= exp0 )); then
        record FAIL mixed "the expiry path did not run" "$value"
        return
    fi
    if (( yields1 <= yields0 )); then
        record FAIL mixed "the yield path did not run" "$value"
        return
    fi
    if (( changes1 <= changes0 )); then
        record FAIL mixed "the weight change path did not run" "$value"
        return
    fi
    if (( lost0 != 0 || stale0 != 0 )); then
        record FAIL mixed "lost=$lost0 stale=$stale0 during the campaign" "$value"
        return
    fi
    if [[ -n "$DSQ_REFUSE" ]] && (( requeues1 < DSQ_REFUSE )); then
        record FAIL mixed "the refused local insert path did not requeue" "$value"
        return
    fi
    if (( DURATION >= 8 )); then
        if (( TH1 <= TH0 )); then
            record FAIL "mixed:parked" \
                "the throttled worker was not parked during the campaign" "$value"
            return
        fi
        if (( PARK_STEP < 2 )); then
            record FAIL "mixed:parked" \
                "the quota refill window did not run during the campaign" "$value"
            return
        fi
        if (( PARKED_TICKS1 <= PARKED_TICKS0 )); then
            record FAIL "mixed:parked" \
                "the parked worker did not run after the quota was lifted" "$value"
            return
        fi
        if ! grep -q 'done=1' "$parked_log" 2>/dev/null; then
            record FAIL "mixed:parked" "the parked worker did not finish" "$value"
            return
        fi
        record PASS "mixed:parked" \
            "the worker was parked $((TH1 - TH0)) times and ran after refill" "$value"
    else
        record BLOCKED "mixed:parked" \
            "the campaign is shorter than 8 s, so the park and refill window did not run"
    fi

    if ! require_stat_keys "$SCHED_LOG" mixed \
        handoffs handoff_max_ns handoff_overdue handoff_orphans handoff_duplicates; then
        return
    fi
    if (( TICK_NS == 0 )); then
        record BLOCKED "mixed:handoff_tick" \
            "no measured tick; the one-tick handoff deadline cannot be checked" "$value"
        return
    fi
    if (( overdue != 0 || orphans != 0 || duplicates != 0 )); then
        record FAIL "mixed:handoff" \
            "overdue=$overdue orphans=$orphans duplicates=$duplicates" "$value"
        return
    fi
    if (( handoffs1 < handoffs0 )); then
        record FAIL "mixed:handoff" "the completed handoff counter went backwards" "$value"
        return
    fi
    if (( handoff_max > TICK_NS )); then
        record FAIL "mixed:handoff" \
            "the longest handoff ${handoff_max} ns exceeds one measured tick ${TICK_NS} ns" "$value"
        return
    fi
    record PASS "mixed:handoff" \
        "$((handoffs1 - handoffs0)) handoffs resolved within one tick, none overdue" "$value"
    record PASS mixed \
        "$progress of ${#tags[@]} mixed workers made progress, lost=0 stale=0" "$value"
}

phase_exit() {
    local lost=0
    local stale=0
    local reweights0
    local reweights1
    local handoffs=0
    local handoff_max=0
    local overdue=0
    local orphans=0
    local duplicates=0
    local repairs=0
    local extra

    lost=$(stat_value "$SCHED_LOG" lost)
    stale=$(stat_value "$SCHED_LOG" stale)
    reweights0=$(stat_value "$SCHED_LOG" reweight)
    handoffs=$(stat_value "$SCHED_LOG" handoffs)
    handoff_max=$(stat_value "$SCHED_LOG" handoff_max_ns)
    overdue=$(stat_value "$SCHED_LOG" handoff_overdue)
    orphans=$(stat_value "$SCHED_LOG" handoff_orphans)
    duplicates=$(stat_value "$SCHED_LOG" handoff_duplicates)
    repairs=$(stat_value "$SCHED_LOG" state_repairs)
    require_scheduler_identity || true
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
    extra=$(printf '"lost":%s,"stale":%s,"reweight_before":%s,"reweight_after":%s,"handoffs":%s,"handoff_max_ns":%s,"tick_ns":%s,"overdue":%s,"orphans":%s,"duplicates":%s,"state_repairs":%s' \
        "$lost" "$stale" "$reweights0" "$reweights1" "$handoffs" \
        "$handoff_max" "$TICK_NS" "$overdue" "$orphans" "$duplicates" "$repairs")
    if (( lost == 0 && stale == 0 )); then
        record PASS lost_tasks "lost=0 stale=0" "$extra"
    else
        record FAIL lost_tasks "lost=$lost stale=$stale" "$extra"
    fi
    if ! require_stat_keys "$SCHED_LOG" exit \
        handoffs handoff_max_ns handoff_overdue handoff_orphans handoff_duplicates; then
        return
    fi
    if (( overdue != 0 || orphans != 0 || duplicates != 0 )); then
        record FAIL handoff_state \
            "overdue=$overdue orphans=$orphans duplicates=$duplicates" "$extra"
        return
    fi
    if (( TICK_NS > 0 && handoff_max > TICK_NS )); then
        record FAIL handoff_deadline \
            "the longest handoff ${handoff_max} ns exceeds one measured tick ${TICK_NS} ns" "$extra"
        return
    fi
    record PASS handoff_deadline \
        "$handoffs handoffs, longest ${handoff_max} ns, no orphan or duplicate" "$extra"
}

#
# Report whether the diagnostic ring lost records. A non-zero overwrite
# count is a FAIL: the transition evidence for that run is incomplete.

trace_check() {
    local line=""
    local overwritten=""
    local extra=""

    if (( TRACE == 0 )); then
        record PASS trace "the diagnostic trace is off"
        return
    fi
    line=$(grep -F 'diagnostics: enabled=' "$SCHED_LOG" 2>/dev/null | tail -n 1 || true)
    if [[ -z "$line" ]]; then
        record FAIL trace "no diagnostic summary in the scheduler log"
        return
    fi
    overwritten=$(printf '%s\n' "$line" | grep -oE 'overwritten=[0-9]+' |
        cut -d= -f2 || true)
    extra=$(printf '%s\n' "$line" | grep -oE 'transitions=[0-9]+|ringed=[0-9]+|overwritten=[0-9]+|task_overflow=[0-9]+' |
        paste -sd, - || true)
    if [[ -z "$overwritten" ]]; then
        record FAIL trace "the diagnostic summary has no overwrite count"
        return
    fi
    if (( overwritten > 0 )); then
        record FAIL trace_overflow "the trace ring overwrote $overwritten records" \
            "\"overwritten\":$overwritten"
        return
    fi
    record PASS trace "the trace ring did not overflow" "\"overwritten\":0,\"summary\":\"$(json_escape "$extra")\""
}

#
# Copy the run artifacts out of the temporary directory before cleanup.

capture_artifacts() {
    local -r dest="$1"

    if [[ -z "$dest" ]]; then
        return 0
    fi
    if ! mkdir -p -- "$dest"; then
        record FAIL artifacts "cannot create $dest"
        return
    fi
    cp -f -- "$SCHED_LOG" "$dest/scheduler.log" 2>/dev/null || true
    dmesg >"$dest/dmesg.txt" 2>/dev/null || true
    cp -f -- "$HARNESS_TMP"/*.log "$dest/" 2>/dev/null || true
    cp -f -- "$HARNESS_TMP"/*.txt "$dest/" 2>/dev/null || true
    record PASS artifacts "$dest"
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
    cgroup_write "$CG_PARKED" cpu.max "max 100000" 2>/dev/null || true
    rmdir -- "$CG_STRESS" "$CG_PARKED" "$CGROUP_PARENT" 2>/dev/null || true
    if [[ ! -e "$CG_STRESS" && ! -e "$CG_PARKED" && ! -e "$CGROUP_PARENT" ]]; then
        record PASS cgroup_cleanup "the stress cgroups were removed"
    else
        record FAIL cgroup_cleanup "a stress cgroup remains"
    fi
}

main() {
    if (( SELFTEST )); then
        harness_init queue_stress_selftest
        run_helper_selftest
        exit 0
    fi
    harness_init queue_stress
    # The trap runs these after stop_scheduler (pushed later) and before
    # the temporary directory is removed (pushed first).
    cleanup_push 'trace_check'
    cleanup_push "capture_artifacts $(printf '%q' "$DUMP_DIR")"
    mkdir -p "$HARNESS_TMP/config"
    export XDG_CONFIG_HOME="$HARNESS_TMP/config"
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
    if (( TRACE )); then
        SCHED_EXTRA+=(--trace)
    fi
    if [[ -n "$DSQ_REFUSE" ]]; then
        SCHED_EXTRA+=(--test-dsq-refuse "$DSQ_REFUSE")
    fi
    start_scheduler "$SCHED_BIN" "$SCHED_LOG" "${SCHED_EXTRA[@]}"
    if ! wait_for_sched_state enabled 10; then
        record FAIL scheduler "state did not become enabled"
        tail -n 5 "$SCHED_LOG" >&2 || true
        exit 1
    fi
    record PASS scheduler "state enabled"
    if ! require_scheduler_identity; then
        exit 2
    fi
    sleep 1.2
    phase_tick

    if (( MIXED )); then
        phase_mixed
        abort_if_dead
        if [[ -n "$YIELD_TO_CMD" ]]; then
            phase_yieldto
            abort_if_dead
        fi
        phase_exit
        phase_faults
        teardown
        return
    fi

    phase_burn
    abort_if_dead
    phase_sleep
    abort_if_dead
    phase_forkexec
    abort_if_dead
    phase_affinity
    abort_if_dead
    phase_migrate
    abort_if_dead
    phase_yield
    abort_if_dead
    phase_reweight
    abort_if_dead
    phase_parked
    abort_if_dead
    phase_yieldto
    abort_if_dead
    phase_exit
    phase_faults
    teardown
}

main "$@"
