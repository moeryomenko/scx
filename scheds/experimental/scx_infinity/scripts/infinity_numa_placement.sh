#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_numa_placement.sh - two-node vNUMA placement harness.
#
# The harness loads scx_infinity in a guest with two vNUMA nodes and checks:
#
#   local_llc     a task woken on an idle CPU stays inside that LLC
#   local_node    a task woken on an idle CPU stays inside that NUMA node
#   remote_spill  with the local node saturated, a new task is placed on the
#                 remote node at wakeup
#   affinity      a task that narrows its mask never runs outside the mask
#   affinity_one  a task narrowed to one CPU never runs on another CPU
#
# A task's CPU is sampled from sched_getcpu() by infinity_workload. The
# probe records the CPU it started on, broadens its affinity to the full
# set, then wakes and samples. The scheduler therefore sees a wakeup whose
# previous CPU is the original CPU, which is the placement input that
# specification section 4.1 defines.
#
# The harness fails closed. It refuses to run without a disposable VM
# (SCX_INFINITY_VM=1), root, two online NUMA nodes and the LLC sysfs file.
# A missing precondition is BLOCKED, never PASS. Any affinity violation is
# a failure.
#
# Usage:
#   SCX_INFINITY_VM=1 sudo \
#     scheds/experimental/scx_infinity/scripts/infinity_numa_placement.sh \
#     [--duration SEC] [--scheduler PATH] [--out FILE] [--check]
#
# Output: one JSON object per line on stdout. The last line is the summary.
# Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED.

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=infinity_harness_lib.sh
. "$SCRIPT_DIR/infinity_harness_lib.sh"

DURATION=2
SCHED_BIN=""
CHECK_ONLY=0
OUT=""
SCHED_LOG=""
WORKLOAD=""
CGROUP_PARENT=""
CG_BURN=""
NODE0_CPUS=""
NODE1_CPUS=""
NODE0_CPU=""
NODE0_LLC=""
DMESG_BASELINE=0

usage() {
    cat >&2 <<'EOF'
usage: infinity_numa_placement.sh [--duration SEC] [--scheduler PATH]
       [--out FILE] [--check]

  --duration SEC     sampling time per probe, default 2
  --scheduler PATH   scx_infinity binary, default SCX_INFINITY_BIN or target/
  --out FILE         also append the JSON Lines records to FILE
  --check            verify preconditions only, load nothing
EOF
}

while (($#)); do
    case "$1" in
        --duration)
            DURATION=${2:?}
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
    require_two_nodes || missing=1
    require_cgroup_cpu || missing=1
    require_cmd cc || missing=1
    require_cmd taskset || missing=1
    require_cmd timeout || missing=1
    require_dmesg || missing=1

    NODE0_CPUS=$(node_cpulist 0)
    NODE1_CPUS=$(node_cpulist 1)
    if [[ -z "$NODE0_CPUS" || -z "$NODE1_CPUS" ]]; then
        record BLOCKED numa_cpulist "node 0 or node 1 has no CPU list"
        missing=1
    else
        record PASS numa_cpulist "node0=$NODE0_CPUS node1=$NODE1_CPUS"
    fi
    if [[ -n "$NODE0_CPUS" ]]; then
        NODE0_CPU=$(cpulist_first "$NODE0_CPUS" || true)
        NODE0_LLC=$(cpu_llc_list "$NODE0_CPU")
        if [[ -z "$NODE0_LLC" ]]; then
            record BLOCKED llc "cpu $NODE0_CPU has no cache/index3/shared_cpu_list"
            missing=1
        else
            record PASS llc "cpu $NODE0_CPU LLC=$NODE0_LLC"
        fi
    fi

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
    CGROUP_PARENT="$root/scx-infinity-numa.$$"
    if ! mkdir -- "$CGROUP_PARENT" 2>/dev/null; then
        record FAIL cgroup "cannot create $CGROUP_PARENT"
        exit 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$CGROUP_PARENT") 2>/dev/null || true"
    if ! cgroup_enable_cpu_at "$CGROUP_PARENT"; then
        record FAIL cgroup "cannot enable the cpu controller in $CGROUP_PARENT"
        exit 1
    fi
    if ! CG_BURN=$(cgroup_create "$CGROUP_PARENT" burn); then
        record FAIL cgroup "cannot create the burn cgroup"
        exit 1
    fi
}

# Run one probe. Args: start_cpu tag mask [broaden]
probe_run() {
    local -r cpu="$1"
    local -r tag="$2"
    local -r mask="$3"
    local -r broaden="${4-}"
    local log="$HARNESS_TMP/${tag}.log"
    local rc=0

    if [[ -n "$broaden" ]]; then
        timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
            taskset -c "$cpu" "$WORKLOAD" probe "$DURATION" "$mask" broaden \
            >"$log" 2>&1 || rc=$?
    else
        timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
            taskset -c "$cpu" "$WORKLOAD" probe "$DURATION" "$mask" \
            >"$log" 2>&1 || rc=$?
    fi
    if (( rc != 0 )); then
        return 1
    fi
    printf '%s\n' "$log"
}

probe_field() {
    local -r log="$1"
    local -r key="$2"

    grep -oE "(^|[[:space:]])${key}=[^[:space:]]+" "$log" 2>/dev/null |
        tail -n 1 | cut -d= -f2 || true
}

all_cpus_in() {
    local -r list="$1"
    local -r allowed="$2"
    local item

    if [[ -z "$list" || "$list" == "none" ]]; then
        return 1
    fi
    IFS=',' read -ra items <<<"$list"
    for item in "${items[@]}"; do
        if ! cpu_in_list "$item" "$allowed"; then
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

run_local_llc() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local first=""
    local extra=""

    if ! log=$(probe_run "$NODE0_CPU" local_llc all broaden); then
        record FAIL local_llc "the probe did not complete"
        return
    fi
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    first=$(probe_field "$log" first_cpu)
    extra=$(printf '"start_cpu":%d,"first_cpu":%s,"llc":"%s","sampled_cpus":"%s","out_of_mask":%s' \
        "$NODE0_CPU" "${first:-0}" "$NODE0_LLC" "${distinct:-none}" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]] || ! all_cpus_in "$distinct" "$NODE0_LLC"; then
        record FAIL local_llc "the task left its local LLC $NODE0_LLC" "$extra"
        return
    fi
    record PASS local_llc "samples $distinct stayed in LLC $NODE0_LLC" "$extra"
}

run_local_node() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local first=""
    local extra=""

    if ! log=$(probe_run "$NODE0_CPU" local_node all broaden); then
        record FAIL local_node "the probe did not complete"
        return
    fi
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    first=$(probe_field "$log" first_cpu)
    extra=$(printf '"start_cpu":%d,"first_cpu":%s,"node_cpus":"%s","sampled_cpus":"%s","out_of_mask":%s' \
        "$NODE0_CPU" "${first:-0}" "$NODE0_CPUS" "${distinct:-none}" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]] || ! all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL local_node "the task left its local NUMA node" "$extra"
        return
    fi
    record PASS local_node "samples $distinct stayed in node 0" "$extra"
}

run_remote_spill() {
    local cpu
    local log=""
    local out_of_mask=""
    local distinct=""
    local first=""
    local extra=""
    local i

    # Two CPU-bound workers per local CPU make the local node crowded, so
    # placement must use an idle CPU in node 1.
    while IFS= read -r cpu; do
        for i in 0 1; do
            if ! start_worker "$CG_BURN" "$cpu" "$HARNESS_TMP/burn_${cpu}_${i}.log" \
                timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
                "$WORKLOAD" burn "$((DURATION + 10))" >/dev/null; then
                record FAIL remote_spill "cannot start a local burner"
                stop_all_workers
                return
            fi
        done
    done < <(cpulist_expand "$NODE0_CPUS")
    sleep 1

    if ! log=$(probe_run "$NODE0_CPU" remote_spill all broaden); then
        stop_all_workers
        record FAIL remote_spill "the probe did not complete"
        return
    fi
    stop_all_workers
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    first=$(probe_field "$log" first_cpu)
    extra=$(printf '"start_cpu":%d,"first_cpu":%s,"sampled_cpus":"%s","node1_cpus":"%s","out_of_mask":%s' \
        "$NODE0_CPU" "${first:-0}" "${distinct:-none}" "$NODE1_CPUS" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]]; then
        record FAIL remote_spill "a sample left the full CPU set" "$extra"
        return
    fi
    if all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL remote_spill "a crowded node 0 kept the task, no remote-node spill" "$extra"
        return
    fi
    record PASS remote_spill "the task spilled out of node 0; samples $distinct" "$extra"
}

run_affinity() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local samples=""
    local extra=""

    if ! log=$(probe_run "$NODE0_CPU" affinity "$NODE0_CPUS"); then
        record FAIL affinity "the probe did not complete"
        return
    fi
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    samples=$(probe_field "$log" samples)
    extra=$(printf '"mask":"%s","sampled_cpus":"%s","samples":%s,"out_of_mask":%s' \
        "$NODE0_CPUS" "${distinct:-none}" "${samples:-0}" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]] || ! all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL affinity "a task ran outside its CPU mask" "$extra"
        return
    fi
    record PASS affinity "the task stayed inside its node 0 mask" "$extra"
}

run_affinity_one() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local extra=""

    if ! log=$(probe_run "$NODE0_CPU" affinity_one "$NODE0_CPU"); then
        record FAIL affinity_one "the probe did not complete"
        return
    fi
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    extra=$(printf '"mask_cpu":%d,"sampled_cpus":"%s","out_of_mask":%s' \
        "$NODE0_CPU" "${distinct:-none}" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]] || ! all_cpus_in "$distinct" "$NODE0_CPU"; then
        record FAIL affinity_one "a task narrowed to one CPU ran elsewhere" "$extra"
        return
    fi
    record PASS affinity_one "the task stayed on CPU $NODE0_CPU" "$extra"
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
    rmdir -- "$CG_BURN" "$CGROUP_PARENT" 2>/dev/null || true
    if [[ ! -e "$CG_BURN" && ! -e "$CGROUP_PARENT" ]]; then
        record PASS cgroup_cleanup "the burn cgroup was removed"
    else
        record FAIL cgroup_cleanup "the burn cgroup remains"
    fi
}

main() {
    harness_init numa_placement
    if [[ -n "$OUT" ]]; then
        HARNESS_JSON_OUT=$OUT
        : >"$OUT"
    fi
    SCHED_LOG="$HARNESS_TMP/scheduler.log"

    if ! preflight; then
        exit 2
    fi
    if (( CHECK_ONLY )); then
        record PASS check_only "preconditions verified; no scheduler loaded"
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

    run_local_llc
    run_local_node
    run_remote_spill
    run_affinity
    run_affinity_one
    teardown
}

main "$@"
