#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_cgroup_harness.sh - cgroup v2 behavior harness for scx_infinity.
#
# The harness creates two cgroups, pins one busy worker of each group to one
# CPU and runs five trials of these cases:
#
#   weight      cpu.weight 100:200, expected runtime ratio 1.8 to 2.2
#   live        cpu.weight 100:100, then 100:200 after five seconds
#   idle        cpu.idle 1, then 0, then 1, and progress after the normal
#               worker stops
#   cpu.max     cpu.max 50000 100000, expected rate 45 to 55 percent and
#               rising throttle counters
#   burst       cpu.max.burst 40000, expected a short burst above quota
#
# Every case needs contention, so both workers are pinned to the same CPU,
# as specification section 7.4 requires.
#
# The harness fails closed. It refuses to run without a disposable VM
# (SCX_INFINITY_VM=1), root and the cgroup files. A missing precondition is
# BLOCKED, never PASS.
#
# Usage:
#   SCX_INFINITY_VM=1 sudo \
#     scheds/experimental/scx_infinity/scripts/infinity_cgroup_harness.sh \
#     [--trials N] [--cpu N] [--window SEC] [--settle SEC] \
#     [--scheduler PATH] [--out FILE] [--check] [--keep]
#
# Output: one JSON object per line on stdout. The last line is the summary.
# Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED.

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=infinity_harness_lib.sh
. "$SCRIPT_DIR/infinity_harness_lib.sh"

TRIALS=5
CPU=0
WINDOW=5
SETTLE=1
SCHED_BIN=""
CHECK_ONLY=0
KEEP=0
OUT=""
CGROUP_PARENT=""
CG_A=""
CG_B=""
SCHED_LOG=""
WORKLOAD=""
PAIR_A_PID=""
DMESG_BASELINE=0
WEIGHT_RATIOS=()
LIVE_RATIOS=()
IDLE_SHARES=()
CPU_MAX_RATES=()
BURST_RATIOS=()

usage() {
    cat >&2 <<'EOF'
usage: infinity_cgroup_harness.sh [--trials N] [--cpu N] [--window SEC]
       [--settle SEC] [--scheduler PATH] [--out FILE] [--check] [--keep]

  --trials N        number of trials, default 5
  --cpu N           CPU that both workers are pinned to, default 0
  --window SEC      measurement window per case, default 5
  --settle SEC      wait after a worker starts, default 1
  --scheduler PATH  scx_infinity binary, default SCX_INFINITY_BIN or target/
  --out FILE        also append the JSON Lines records to FILE
  --check           verify preconditions only, start nothing
  --keep            keep the cgroups for inspection after the run
EOF
}

while (($#)); do
    case "$1" in
        --trials)
            TRIALS=${2:?}
            shift
            ;;
        --cpu)
            CPU=${2:?}
            shift
            ;;
        --window)
            WINDOW=${2:?}
            shift
            ;;
        --settle)
            SETTLE=${2:?}
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
        --check)
            CHECK_ONLY=1
            ;;
        --keep)
            KEEP=1
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

if ! [[ "$TRIALS" =~ ^[1-9][0-9]*$ && "$CPU" =~ ^[0-9]+$ &&
        "$WINDOW" =~ ^[1-9][0-9]*$ && "$SETTLE" =~ ^[0-9]+$ ]]; then
    printf 'numeric arguments are invalid\n' >&2
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

setup_cgroups() {
    local root=""

    if ! root=$(cgroup2_root); then
        record FAIL cgroup "the cgroup v2 mount disappeared"
        exit 1
    fi
    CGROUP_PARENT="$root/scx-infinity-cgroup.$$"
    if ! mkdir -- "$CGROUP_PARENT" 2>/dev/null; then
        record FAIL cgroup "cannot create $CGROUP_PARENT"
        exit 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$CGROUP_PARENT") 2>/dev/null || true"
    if ! cgroup_enable_cpu_at "$CGROUP_PARENT"; then
        record FAIL cgroup "cannot enable the cpu controller in $CGROUP_PARENT"
        exit 1
    fi
    if ! CG_A=$(cgroup_create "$CGROUP_PARENT" a); then
        record FAIL cgroup "cannot create group a"
        exit 1
    fi
    if ! CG_B=$(cgroup_create "$CGROUP_PARENT" b); then
        record FAIL cgroup "cannot create group b"
        exit 1
    fi
    cleanup_push 'stop_all_workers'
    if (( KEEP )); then
        note cgroup "keep requested; groups at $CGROUP_PARENT"
    fi
}

reset_groups() {
    cgroup_write "$CG_A" cpu.weight 100 || {
        record FAIL cgroup "cannot set cpu.weight of group a"
        return 1
    }
    cgroup_write "$CG_B" cpu.weight 100 || {
        record FAIL cgroup "cannot set cpu.weight of group b"
        return 1
    }
    cgroup_write "$CG_A" cpu.max "max 100000" || {
        record FAIL cgroup "cannot clear cpu.max of group a"
        return 1
    }
    cgroup_write "$CG_B" cpu.max "max 100000" || {
        record FAIL cgroup "cannot clear cpu.max of group b"
        return 1
    }
    cgroup_write "$CG_A" cpu.max.burst 0 || return 1
    cgroup_write "$CG_B" cpu.max.burst 0 || return 1
    cgroup_write "$CG_A" cpu.idle 0 || return 1
    cgroup_write "$CG_B" cpu.idle 0 || return 1
}

start_burn() {
    local -r cg="$1"
    local -r tag="$2"

    start_worker "$cg" "$CPU" "$HARNESS_TMP/${tag}.log" "$WORKLOAD" burn 3600 \
        >/dev/null
}

start_pair() {
    if ! start_burn "$CG_A" worker_a; then
        record FAIL worker "cannot start worker a"
        return 1
    fi
    PAIR_A_PID=$HARNESS_LAST_PID
    if ! start_burn "$CG_B" worker_b; then
        record FAIL worker "cannot start worker b"
        return 1
    fi
}

stop_pair() {
    stop_all_workers
    PAIR_A_PID=""
}

check_scheduler_health() {
    local -r tag="$1"

    if ! scheduler_alive; then
        record FAIL "$tag:scheduler" "the scheduler exited during the case"
        return 1
    fi
    if [[ "$(sched_state)" != "enabled" ]]; then
        record FAIL "$tag:scheduler" "/sys/kernel/sched_ext/state is not enabled"
        return 1
    fi
}

# Print the two usage_usec deltas over one window.
measure_pair() {
    local -r cg_a="$1"
    local -r cg_b="$2"
    local -r seconds="$3"
    local a0
    local b0
    local a1
    local b1

    a0=$(cpu_stat_value "$cg_a" usage_usec)
    b0=$(cpu_stat_value "$cg_b" usage_usec)
    sleep "$seconds"
    a1=$(cpu_stat_value "$cg_a" usage_usec)
    b1=$(cpu_stat_value "$cg_b" usage_usec)
    if [[ -z "$a0" || -z "$b0" || -z "$a1" || -z "$b1" ]]; then
        return 1
    fi
    printf '%s %s\n' "$((a1 - a0))" "$((b1 - b0))"
}

run_weight_trial() {
    local -r trial="$1"
    local pair=""
    local ua=0
    local ub=0
    local ratio=""
    local status=""
    local extra=""

    reset_groups || return
    cgroup_write "$CG_A" cpu.weight 100 || {
        record FAIL weight_ratio "trial $trial cannot set weight a"
        return
    }
    cgroup_write "$CG_B" cpu.weight 200 || {
        record FAIL weight_ratio "trial $trial cannot set weight b"
        return
    }
    start_pair || { stop_pair; return; }
    sleep "$SETTLE"
    if ! pair=$(measure_pair "$CG_A" "$CG_B" "$WINDOW"); then
        stop_pair
        record FAIL weight_ratio "trial $trial cannot read cpu.stat usage_usec"
        return
    fi
    if ! check_scheduler_health weight_ratio; then
        stop_pair
        return
    fi
    stop_pair
    read -r ua ub <<<"$pair"
    ratio=$(fp_ratio "$ua" "$ub")
    if num_in_range "$ratio" 1.8 2.2; then
        status=PASS
    else
        status=FAIL
    fi
    WEIGHT_RATIOS+=("$ratio")
    extra=$(printf '"trial":%d,"a_usec":%s,"b_usec":%s,"ratio":%s' \
        "$trial" "$ua" "$ub" "$ratio")
    record "$status" weight_ratio \
        "trial $trial weight 100:200 ratio $ratio, expected 1.8 to 2.2" "$extra"
}

run_live_trial() {
    local -r trial="$1"
    local pair1=""
    local pair2=""
    local a1=0
    local b1=0
    local a2=0
    local b2=0
    local ratio1=""
    local ratio2=""
    local status="FAIL"
    local extra=""

    reset_groups || return
    start_pair || { stop_pair; return; }
    sleep "$SETTLE"
    if ! pair1=$(measure_pair "$CG_A" "$CG_B" "$WINDOW"); then
        stop_pair
        record FAIL live_weight "trial $trial cannot read cpu.stat usage_usec"
        return
    fi
    read -r a1 b1 <<<"$pair1"
    cgroup_write "$CG_B" cpu.weight 200 || {
        stop_pair
        record FAIL live_weight "trial $trial cannot change the live weight"
        return
    }
    sleep 0.2
    if ! pair2=$(measure_pair "$CG_A" "$CG_B" "$WINDOW"); then
        stop_pair
        record FAIL live_weight "trial $trial cannot read the second window"
        return
    fi
    if ! check_scheduler_health live_weight; then
        stop_pair
        return
    fi
    stop_pair
    read -r a2 b2 <<<"$pair2"
    ratio1=$(fp_ratio "$a1" "$b1")
    ratio2=$(fp_ratio "$a2" "$b2")
    if num_in_range "$ratio1" 0.85 1.15 && num_in_range "$ratio2" 1.8 2.2; then
        status=PASS
    fi
    LIVE_RATIOS+=("$ratio2")
    extra=$(printf '"trial":%d,"before_ratio":%s,"after_ratio":%s,"before_a_usec":%s,"before_b_usec":%s,"after_a_usec":%s,"after_b_usec":%s' \
        "$trial" "$ratio1" "$ratio2" "$a1" "$b1" "$a2" "$b2")
    record "$status" live_weight \
        "trial $trial ratio before $ratio1 after $ratio2, expected 1:1 then 1:2" "$extra"
}

run_idle_trial() {
    local -r trial="$1"
    local pair=""
    local a=0
    local b=0
    local on1=""
    local off=""
    local on2=""
    local progress=0
    local a0=0
    local b0=0
    local b1=0
    local status="FAIL"
    local extra=""
    local -r idle_window=3
    local -r progress_window=2

    reset_groups || return
    cgroup_write "$CG_B" cpu.idle 1 || {
        record FAIL cpu_idle "trial $trial cannot set cpu.idle"
        return
    }
    start_pair || { stop_pair; return; }
    sleep "$SETTLE"

    if ! pair=$(measure_pair "$CG_A" "$CG_B" "$idle_window"); then
        stop_pair
        record FAIL cpu_idle "trial $trial cannot read cpu.stat"
        return
    fi
    read -r a b <<<"$pair"
    on1=$(fp_scale "$b" "$((a + b))")

    cgroup_write "$CG_B" cpu.idle 0 || {
        stop_pair
        record FAIL cpu_idle "trial $trial cannot clear cpu.idle"
        return
    }
    sleep 0.2
    if ! pair=$(measure_pair "$CG_A" "$CG_B" "$idle_window"); then
        stop_pair
        record FAIL cpu_idle "trial $trial cannot read the non-idle window"
        return
    fi
    read -r a b <<<"$pair"
    off=$(fp_scale "$b" "$((a + b))")

    cgroup_write "$CG_B" cpu.idle 1 || {
        stop_pair
        record FAIL cpu_idle "trial $trial cannot set cpu.idle again"
        return
    }
    sleep 0.2
    if ! pair=$(measure_pair "$CG_A" "$CG_B" "$idle_window"); then
        stop_pair
        record FAIL cpu_idle "trial $trial cannot read the second idle window"
        return
    fi
    read -r a b <<<"$pair"
    on2=$(fp_scale "$b" "$((a + b))")

    # The normal worker stops, so the idle worker must make progress.
    stop_worker "$PAIR_A_PID"
    PAIR_A_PID=""
    a0=$(cpu_stat_value "$CG_B" usage_usec)
    sleep "$progress_window"
    b1=$(cpu_stat_value "$CG_B" usage_usec)
    if [[ -n "$a0" && -n "$b1" ]]; then
        progress=$((b1 - a0))
    fi

    if ! check_scheduler_health cpu_idle; then
        stop_pair
        return
    fi
    stop_pair

    if num_in_range "$on1" 0 0.05 &&
       num_in_range "$off" 0.20 0.80 &&
       num_in_range "$on2" 0 0.05 && (( progress > 0 )); then
        status=PASS
    fi
    IDLE_SHARES+=("$on1")
    extra=$(printf '"trial":%d,"idle_share_on1":%s,"share_off":%s,"idle_share_on2":%s,"progress_usec":%s' \
        "$trial" "$on1" "$off" "$on2" "$progress")
    record "$status" cpu_idle \
        "trial $trial idle share $on1 then $off then $on2, progress ${progress}us" "$extra"
}

run_cpu_max_trial() {
    local -r trial="$1"
    local a0=0
    local a1=0
    local used=0
    local rate=""
    local nr0=0
    local nr1=0
    local th0=0
    local th1=0
    local status="FAIL"
    local extra=""

    reset_groups || return
    cgroup_write "$CG_A" cpu.max "50000 100000" || {
        record FAIL cpu_max "trial $trial cannot set cpu.max"
        return
    }
    cgroup_write "$CG_A" cpu.max.burst 0 || {
        record FAIL cpu_max "trial $trial cannot clear cpu.max.burst"
        return
    }
    if ! start_burn "$CG_A" max_worker >/dev/null; then
        record FAIL cpu_max "trial $trial cannot start the worker"
        return
    fi
    sleep "$SETTLE"
    a0=$(cpu_stat_value "$CG_A" usage_usec)
    nr0=$(cpu_stat_value "$CG_A" nr_throttled)
    th0=$(cpu_stat_value "$CG_A" throttled_usec)
    sleep "$WINDOW"
    a1=$(cpu_stat_value "$CG_A" usage_usec)
    nr1=$(cpu_stat_value "$CG_A" nr_throttled)
    th1=$(cpu_stat_value "$CG_A" throttled_usec)
    if ! check_scheduler_health cpu_max; then
        stop_pair
        return
    fi
    stop_pair
    used=$((a1 - a0))
    rate=$(fp_scale "$used" "$((WINDOW * 1000000))")
    if num_in_range "$rate" 0.45 0.55 &&
       (( nr1 > nr0 )) && (( th1 > th0 )); then
        status=PASS
    fi
    CPU_MAX_RATES+=("$rate")
    extra=$(printf '"trial":%d,"rate":%s,"usage_usec":%s,"nr_throttled_before":%s,"nr_throttled_after":%s,"throttled_usec_before":%s,"throttled_usec_after":%s' \
        "$trial" "$rate" "$used" "$nr0" "$nr1" "$th0" "$th1")
    record "$status" cpu_max \
        "trial $trial rate $rate, expected 0.45 to 0.55 and rising throttle counters" "$extra"
}

run_burst_trial() {
    local -r trial="$1"
    local b0=0
    local b1=0
    local burst_used=0
    local burst=""
    local s0=0
    local s1=0
    local steady_used=0
    local steady=""
    local nr0=0
    local nr1=0
    local status="FAIL"
    local extra=""

    reset_groups || return
    cgroup_write "$CG_A" cpu.max "50000 100000" || {
        record FAIL cpu_max_burst "trial $trial cannot set cpu.max"
        return
    }
    cgroup_write "$CG_A" cpu.max.burst 40000 || {
        record FAIL cpu_max_burst "trial $trial cannot set cpu.max.burst"
        return
    }
    # Let the group underspend one period, so it earns burst credit.
    sleep 0.5
    if ! start_burn "$CG_A" burst_worker >/dev/null; then
        record FAIL cpu_max_burst "trial $trial cannot start the worker"
        return
    fi
    b0=$(cpu_stat_value "$CG_A" usage_usec)
    sleep 0.3
    b1=$(cpu_stat_value "$CG_A" usage_usec)
    burst_used=$((b1 - b0))
    burst=$(fp_scale "$burst_used" 300000)

    nr0=$(cpu_stat_value "$CG_A" nr_throttled)
    sleep "$WINDOW"
    s0=$(cpu_stat_value "$CG_A" usage_usec)
    sleep 1
    s1=$(cpu_stat_value "$CG_A" usage_usec)
    nr1=$(cpu_stat_value "$CG_A" nr_throttled)
    if ! check_scheduler_health cpu_max_burst; then
        stop_pair
        return
    fi
    stop_pair
    steady_used=$((s1 - s0))
    steady=$(fp_scale "$steady_used" 1000000)
    if num_in_range "$burst" 0.52 1.0 &&
       num_in_range "$steady" 0.45 0.55 && (( nr1 > nr0 )); then
        status=PASS
    fi
    BURST_RATIOS+=("$burst")
    extra=$(printf '"trial":%d,"burst_ratio":%s,"burst_usage_usec":%s,"steady_ratio":%s,"nr_throttled_before":%s,"nr_throttled_after":%s' \
        "$trial" "$burst" "$burst_used" "$steady" "$nr0" "$nr1")
    record "$status" cpu_max_burst \
        "trial $trial burst ratio $burst and steady ratio $steady" "$extra"
}

teardown() {
    local faults=""
    local lost=0
    local stale=0

    stop_all_workers
    if cgroup_procs_empty "$CG_A" && cgroup_procs_empty "$CG_B"; then
        record PASS cgroup_empty "both worker cgroups are empty"
    else
        record FAIL cgroup_empty "a worker cgroup still has processes"
    fi

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

    lost=$(stat_value "$SCHED_LOG" lost)
    stale=$(stat_value "$SCHED_LOG" stale)
    if (( lost == 0 && stale == 0 )); then
        record PASS lost_tasks "lost=0 stale=0"
    else
        record FAIL lost_tasks "lost=$lost stale=$stale"
    fi

    faults=$(dmesg_new_faults "$DMESG_BASELINE")
    if [[ -z "$faults" ]]; then
        record PASS dmesg "no scheduler fault in dmesg"
    else
        record FAIL dmesg "kernel fault: $(printf '%s' "$faults" | head -n 1)"
    fi

    if (( KEEP )); then
        return 0
    fi
    rmdir -- "$CG_A" "$CG_B" "$CGROUP_PARENT" 2>/dev/null || true
    if [[ ! -e "$CG_A" && ! -e "$CG_B" && ! -e "$CGROUP_PARENT" ]]; then
        record PASS cgroup_cleanup "worker cgroups removed"
    else
        record FAIL cgroup_cleanup "worker cgroups remain"
    fi
}

note_summary() {
    local -r label="$1"
    shift

    if (($# == 0)); then
        return 0
    fi
    note "$label" "median $label over $# trials" "$(printf '"median":%s' "$(median_of "$@")")"
}

main() {
    local trial

    harness_init cgroup
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

    setup_cgroups
    DMESG_BASELINE=$(dmesg_lines)
    start_scheduler "$SCHED_BIN" "$SCHED_LOG"
    if ! wait_for_sched_state enabled 10; then
        record FAIL scheduler "state did not become enabled"
        tail -n 5 "$SCHED_LOG" >&2 || true
        exit 1
    fi
    record PASS scheduler "state enabled"

    for (( trial=1; trial <= TRIALS; trial++ )); do
        run_weight_trial "$trial"
        run_live_trial "$trial"
        run_idle_trial "$trial"
        run_cpu_max_trial "$trial"
        run_burst_trial "$trial"
    done

    note_summary weight_ratio_median "${WEIGHT_RATIOS[@]}"
    note_summary live_ratio_median "${LIVE_RATIOS[@]}"
    note_summary idle_share_median "${IDLE_SHARES[@]}"
    note_summary cpu_max_rate_median "${CPU_MAX_RATES[@]}"
    note_summary burst_ratio_median "${BURST_RATIOS[@]}"

    teardown
}

main "$@"
