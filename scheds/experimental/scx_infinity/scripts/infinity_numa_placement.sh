#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_numa_placement.sh - two-node vNUMA placement harness.
#
# The harness loads scx_infinity in a guest with two vNUMA nodes and checks:
#
#   previous_cpu     a task woken on an idle CPU runs on that CPU again
#   local_llc        a task woken on an idle CPU stays inside that LLC
#   local_node       a task woken on an idle CPU stays inside that NUMA node
#   llc_before_node  the local LLC share is at least the local node share
#   steal_llc        a peer inside the same LLC steals, and only the LLC tier
#                    counter moves
#   steal_node       a peer inside the same node but in another LLC steals, and
#                    only the node tier counter moves
#   no_remote_steal  an idle node does not take work from the other node
#   no_remote_steal_local
#                    the same, with eligible local runnable work present
#   no_remote_steal_parked
#                    the same, with the local work quota-parked
#   remote_spill     with every local CPU busy, a new task is placed on the
#                    remote node at wakeup
#   remote_spill_mask the mask forbids the remote node, so no spill happens
#   remote_spill_parked
#                    quota-parked local work does not push a new task to the
#                    remote node while a local CPU is idle
#   remote_spill_affinity
#                    a local CPU that is idle runs the new task, so affinity-
#                    ineligible local work does not cause a remote spill
#   affinity         a task that narrows its mask never runs outside the mask
#   affinity_one     a task narrowed to one CPU never runs on another CPU
#   migration        a task moved to the other node keeps running there
#
# Every remote-spill case reads the per-CPU idle share from /proc/stat
# before the probe. A remote sample is a failure when a local CPU was
# idle, and a local sample is a failure when every local CPU was busy.
# That is the placement oracle: work moves to another node only when no
# affinity-allowed, unthrottled local CPU can run it. Quota-parked local
# work is tested separately from eligible local work.
#
# A task's CPU is sampled from sched_getcpu() by infinity_workload. The
# probe records the CPU it started on, broadens its affinity to the full
# set, then wakes and samples. The scheduler therefore sees a wakeup whose
# previous CPU is the original CPU, which is the placement input that
# specification section 4.1 defines.
#
# The steal cases use the task mask to attribute a steal to one tier. A task
# whose mask names only the two CPUs of one LLC can only be stolen inside that
# LLC. A task whose mask names one CPU of each of the two LLCs of one node can
# only be stolen inside that node. The counters are therefore read against a
# condition that leaves exactly one tier reachable.
#
# The harness fails closed. It refuses to run without a disposable VM
# (SCX_INFINITY_VM=1), root, two online NUMA nodes and the LLC sysfs file.
# A missing precondition is BLOCKED, never PASS. Any affinity violation is
# a failure. The active scheduler must be scx_infinity; a mismatch blocks
# the run.
#
# Usage:
#   SCX_INFINITY_VM=1 sudo \
#     scheds/experimental/scx_infinity/scripts/infinity_numa_placement.sh \
#     [--duration SEC] [--scheduler PATH] [--out FILE] [--case NAME] [--check]
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
CASE=""
SCHED_LOG=""
WORKLOAD=""
CGROUP_PARENT=""
CG_BURN=""
CG_NODE1=""
CG_PARKED=""
NODE0_CPUS=""
NODE1_CPUS=""
NODE0_CPU=""
NODE0_LLC=""
NODE0_LLC_PEER=""
NODE0_LLC2=""
NODE0_LLC2_CPU=""
NODE0_LLC2_PEER=""
NODE1_LLC=""
DMESG_BASELINE=0
LOCAL_LLC_SHARE=0
LOCAL_NODE_SHARE=0

# The lowest share of the probe samples that must stay on the previous CPU,
# in the local LLC or in the local node. The guest keeps its own tasks, so
# a wakeup can find the preferred CPU busy and move to another CPU of the
# same domain. That is the placement order of specification section 4.1, so
# the case measures the preference over the whole sample window instead of
# demanding that no sample ever leaves the domain.
LOCALITY_MIN_SHARE_PCT=${LOCALITY_MIN_SHARE_PCT:-90}

# A local CPU with at least this idle share before a probe means a local
# CPU was available. A remote sample is then a placement failure.
LOCAL_IDLE_PCT=${LOCAL_IDLE_PCT:-50}

# The previous-CPU probe. A 1 ms sleeper can still be running when its
# wakeup is handled, so prev_cpu is not idle yet. The probe sleeps long
# enough for the CPU to go idle, then records the CPU it wakes on.
PREV_ROUNDS=${PREV_ROUNDS:-20}
PREV_SLEEP_MS=${PREV_SLEEP_MS:-50}
PREV_MIN_SHARE_PCT=${PREV_MIN_SHARE_PCT:-90}
PREV_PROBE=""

# The number of probe windows a locality case runs. A task of the guest on
# the second CPU of the local LLC can hold a whole window. The case then
# looks for a window in which the local domain was available.
LOCALITY_ATTEMPTS=${LOCALITY_ATTEMPTS:-3}

usage() {
    cat >&2 <<'EOF'
usage: infinity_numa_placement.sh [--duration SEC] [--scheduler PATH]
       [--out FILE] [--case NAME] [--check]

  --duration SEC     sampling time per probe, default 2
  --scheduler PATH   scx_infinity binary, default SCX_INFINITY_BIN or target/
  --out FILE         also append the JSON Lines records to FILE
  --case NAME        run one named case after load, then exit
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
        --case)
            CASE=${2:?}
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

# Compile the previous-CPU probe into the harness temporary directory.
prepare_prev_probe() {
    local source="$HARNESS_TMP/infinity_prev_cpu.c"
    local cc_log="$HARNESS_TMP/prev-cc.log"

    PREV_PROBE="$HARNESS_TMP/infinity_prev_cpu"
    cat >"$source" <<'CPROBE_EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define CPU_LIMIT 1024

static void sleep_ms(long milliseconds)
{
	struct timespec ts = {
		.tv_sec	 = milliseconds / 1000,
		.tv_nsec = (milliseconds % 1000) * 1000000LL,
	};

	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

static void set_all(cpu_set_t *set)
{
	int cpu;

	CPU_ZERO(set);
	for (cpu = 0; cpu < CPU_LIMIT; cpu++)
		CPU_SET(cpu, set);
}

int main(int argc, char **argv)
{
	cpu_set_t one;
	cpu_set_t all;
	long sleep_ms_value;
	int start_cpu;
	int rounds;
	int hits = 0;
	int i;

	if (argc < 4) {
		fprintf(stderr, "usage: %s START_CPU SLEEP_MS ROUNDS\n", argv[0]);
		return 2;
	}
	start_cpu = atoi(argv[1]);
	sleep_ms_value = atol(argv[2]);
	rounds = atoi(argv[3]);
	if (start_cpu < 0 || start_cpu >= CPU_LIMIT || sleep_ms_value <= 0 ||
	    rounds <= 0)
		return 2;
	set_all(&all);
	for (i = 0; i < rounds; i++) {
		int cpu;

		CPU_ZERO(&one);
		CPU_SET(start_cpu, &one);
		if (sched_setaffinity(0, sizeof(one), &one) != 0)
			return 1;
		if (sched_setaffinity(0, sizeof(all), &all) != 0)
			return 1;
		sleep_ms(sleep_ms_value);
		cpu = sched_getcpu();
		if (cpu == start_cpu)
			hits++;
		printf("%d\n", cpu);
	}
	printf("hits=%d rounds=%d\n", hits, rounds);
	return 0;
}
CPROBE_EOF
    if ! cc -O2 -Wall -Wextra -o "$PREV_PROBE" "$source" 2>"$cc_log"; then
        record FAIL prev_cpu_build "cc failed: $(tail -n 3 "$cc_log" 2>/dev/null || true)"
        return 1
    fi
    record PASS prev_cpu_build "compiled $source"
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
        NODE0_LLC_PEER=$(llc_other_cpu "$NODE0_LLC" "$NODE0_CPU" || true)
        if [[ -z "$NODE0_LLC_PEER" ]]; then
            record BLOCKED llc_peer "the LLC of cpu $NODE0_CPU has no second CPU"
            missing=1
        else
            record PASS llc_peer "LLC $NODE0_LLC peer cpu=$NODE0_LLC_PEER"
        fi
        NODE0_LLC2_CPU=$(node_cpu_outside_llc "$NODE0_CPUS" "$NODE0_LLC" || true)
        if [[ -z "$NODE0_LLC2_CPU" ]]; then
            record BLOCKED llc2 "node 0 has no second LLC"
            missing=1
        else
            NODE0_LLC2=$(cpu_llc_list "$NODE0_LLC2_CPU")
            NODE0_LLC2_PEER=$(llc_other_cpu "$NODE0_LLC2" "$NODE0_LLC2_CPU" || true)
            if [[ -z "$NODE0_LLC2_PEER" ]]; then
                record BLOCKED llc2 "the second LLC of node 0 has no second CPU"
                missing=1
            else
                record PASS llc2 "node 0 second LLC=$NODE0_LLC2 cpu=$NODE0_LLC2_CPU peer=$NODE0_LLC2_PEER"
            fi
        fi
    fi
    if [[ -n "$NODE1_CPUS" ]]; then
        local node1_cpu
        node1_cpu=$(cpulist_first "$NODE1_CPUS" || true)
        NODE1_LLC=$(cpu_llc_list "$node1_cpu")
        if [[ -z "$NODE1_LLC" ]]; then
            record BLOCKED llc_node1 "cpu $node1_cpu has no cache/index3/shared_cpu_list"
            missing=1
        else
            record PASS llc_node1 "cpu $node1_cpu LLC=$NODE1_LLC"
        fi
    fi

    if [[ -z "$SCHED_BIN" ]]; then
        SCHED_BIN=$(resolve_scheduler || true)
    fi
    if [[ -z "$SCHED_BIN" ]]; then
        # A guest often carries the crate tree without the repository. Look
        # for the build next to the scripts, next to the crate and next to
        # the workspace.
        local candidate
        for candidate in "$SCRIPT_DIR/scx_infinity" \
            "$SCRIPT_DIR/../target/release/scx_infinity" \
            "$SCRIPT_DIR/../target/debug/scx_infinity" \
            "$SCRIPT_DIR/../../../target/release/scx_infinity" \
            "$SCRIPT_DIR/../../../target/debug/scx_infinity"; do
            if [[ -x "$candidate" ]]; then
                SCHED_BIN=$candidate
                break
            fi
        done
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
    if (( missing == 0 )); then
        prepare_prev_probe || missing=1
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
    if ! CG_NODE1=$(cgroup_create "$CGROUP_PARENT" node1); then
        record FAIL cgroup "cannot create the node 1 cgroup"
        exit 1
    fi
    if ! CG_PARKED=$(cgroup_create "$CGROUP_PARENT" parked); then
        record FAIL cgroup "cannot create the parked cgroup"
        exit 1
    fi
    cleanup_push 'stop_all_workers'
}

# Print the CPU of a task, or an empty string when the task is gone.
worker_cpu() {
    local -r pid="$1"
    local stat=""
    local rest=""

    [[ -r "/proc/$pid/stat" ]] || return 1
    stat=$(<"/proc/$pid/stat") || return 1
    rest=${stat#*") "}
    awk '{ if (NF >= 37) print $37; else print -1 }' <<<"$rest"
}

# Print the consumed CPU time of a task in clock ticks.
worker_cpu_time() {
    local -r pid="$1"
    local stat=""
    local rest=""

    [[ -r "/proc/$pid/stat" ]] || return 1
    stat=$(<"/proc/$pid/stat") || return 1
    rest=${stat#*") "}
    awk '{ print $12 + $13 }' <<<"$rest"
}

# Poll every task of one cgroup and print every CPU one of them ran on. The
# children of a workload inherit the cgroup, so this covers the whole load
# and not only the process the harness started.
observe_cgroup_cpus_in() {
    local -r cg="$1"
    local -r seconds="$2"
    local end
    local pid
    local cpu
    local seen=""

    end=$(( $(date +%s) + seconds ))
    while (( $(date +%s) < end )); do
        while read -r pid; do
            [[ -n "$pid" ]] || continue
            cpu=$(worker_cpu "$pid" 2>/dev/null || true)
            [[ -z "$cpu" || "$cpu" == "-1" ]] && continue
            if [[ ",$seen," != *",$cpu,"* ]]; then
                seen="$seen,$cpu"
            fi
        done <"$cg/cgroup.procs" 2>/dev/null || true
        sleep 0.05
    done
    printf '%s\n' "${seen#,}"
}

observe_cgroup_cpus() {
    observe_cgroup_cpus_in "$CG_BURN" "$1"
}

# Print the other CPU of one LLC.
llc_other_cpu() {
    local -r llc="$1"
    local -r exclude="$2"
    local cpu

    for cpu in $(cpulist_expand "$llc"); do
        if [[ "$cpu" != "$exclude" ]]; then
            printf '%s\n' "$cpu"
            return 0
        fi
    done
    return 1
}

# Print a CPU of one node that is not part of the given LLC.
node_cpu_outside_llc() {
    local -r node="$1"
    local -r llc="$2"
    local cpu

    for cpu in $(cpulist_expand "$node"); do
        if ! cpu_in_list "$cpu" "$llc"; then
            printf '%s\n' "$cpu"
            return 0
        fi
    done
    return 1
}

# Wait until the loader printed a new statistics line.
wait_for_stat_tick() {
    local -r seconds="$1"
    local first=""
    local current=""
    local i

    first=$(stats_line "$SCHED_LOG")
    for (( i = 0; i < seconds * 20; i++ )); do
        current=$(stats_line "$SCHED_LOG")
        if [[ -n "$current" && "$current" != "$first" ]]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
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

# Print the share of the probe samples that fell into the given cpulist, in
# percent with two decimals.
probe_share() {
    local -r log="$1"
    local -r list="$2"
    local counts=""
    local total=0
    local inside=0

    counts=$(probe_field "$log" counts)
    total=$(probe_field "$log" samples)
    if [[ -z "$counts" || "$counts" == "none" || -z "$total" || "$total" == "0" ]]; then
        printf '0.00\n'
        return 1
    fi
    inside=$(printf '%s\n' "$counts" | awk -v list="$list" '
        BEGIN {
            n = split(list, part, ",")
            for (i = 1; i <= n; i++) {
                lo = part[i]
                hi = lo
                if (index(lo, "-")) {
                    split(lo, r, "-")
                    lo = r[1]
                    hi = r[2]
                }
                for (c = lo; c <= hi; c++)
                    want[c] = 1
            }
        }
        {
            n = split($0, parts, ",")
            for (i = 1; i <= n; i++) {
                split(parts[i], kv, ":")
                if (kv[1] in want)
                    sum += kv[2]
            }
        }
        END { print sum + 0 }')
    awk -v inside="$inside" -v total="$total" \
        'BEGIN { printf "%.2f", 100 * inside / total }'
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

# Run the probe up to LOCALITY_ATTEMPTS times and print the highest share of
# the samples that fell into the given cpulist. A sample outside the allowed
# CPU set ends the measurement at once, because that is an affinity
# violation and no retry can hide it.
#
# The probe needs an idle CPU in its local LLC. The guest keeps its own
# tasks, so a task on the second CPU of the LLC can hold the whole window.
# The placement order of specification section 4.1 then sends the probe to
# another core of the same node, which is correct behaviour. The retry
# looks for a window in which the local LLC was available.
locality_best_share() {
    local -r list="$1"
    local attempt=0
    local best=0
    local log=""
    local share=""
    local out=""

    while (( attempt < LOCALITY_ATTEMPTS )); do
        attempt=$((attempt + 1))
        if ! log=$(probe_run "$NODE0_CPU" "locality_$attempt" all broaden); then
            printf '0.00\n'
            return 1
        fi
        out=$(probe_field "$log" out_of_mask)
        if [[ "${out:-1}" != "0" ]]; then
            printf '0.00\n'
            return 1
        fi
        share=$(probe_share "$log" "$list")
        if awk -v a="$share" -v b="$best" 'BEGIN { exit !(a > b) }'; then
            best=$share
        fi
    done
    printf '%s\n' "$best"
}

run_local_llc() {
    local share=""
    local extra=""

    if ! share=$(locality_best_share "$NODE0_LLC"); then
        record FAIL local_llc "the probe did not complete or ran outside the allowed CPU set"
        return
    fi
    extra=$(printf '"start_cpu":%d,"llc":"%s","llc_share_pct":%s,"attempts":%d' \
        "$NODE0_CPU" "$NODE0_LLC" "${share:-0}" "$LOCALITY_ATTEMPTS")
    if ! num_in_range "$share" "$LOCALITY_MIN_SHARE_PCT" 100; then
        record FAIL local_llc "the task left its local LLC $NODE0_LLC in every attempt" "$extra"
        return
    fi
    LOCAL_LLC_SHARE=$share
    record PASS local_llc "$share percent of the samples stayed in LLC $NODE0_LLC" "$extra"
}

run_local_node() {
    local share=""
    local extra=""

    if ! share=$(locality_best_share "$NODE0_CPUS"); then
        record FAIL local_node "the probe did not complete or ran outside the allowed CPU set"
        return
    fi
    extra=$(printf '"start_cpu":%d,"node_cpus":"%s","node_share_pct":%s,"attempts":%d' \
        "$NODE0_CPU" "$NODE0_CPUS" "${share:-0}" "$LOCALITY_ATTEMPTS")
    if ! num_in_range "$share" "$LOCALITY_MIN_SHARE_PCT" 100; then
        record FAIL local_node "the task left its local NUMA node in every attempt" "$extra"
        return
    fi
    LOCAL_NODE_SHARE=$share
    record PASS local_node "$share percent of the samples stayed in node 0" "$extra"
}

# The previous CPU is the first placement input of specification section
# 4.1. Each round pins the probe to CPU 0, broadens the mask, sleeps long
# enough for CPU 0 to go idle, and records the CPU it wakes on. The case
# only judges a round when CPU 0 was idle before the probe.
run_previous_cpu() {
    local idle=0
    local out=""
    local hits=""
    local rounds=""
    local share=""
    local extra=""

    if [[ -z "$PREV_PROBE" || ! -x "$PREV_PROBE" ]]; then
        record BLOCKED previous_cpu "the previous-CPU probe was not built"
        return
    fi
    stop_all_workers
    sleep 1
    idle=$(cpu_idle_percent "$NODE0_CPU" 1000)
    if ! num_in_range "$idle" "$PREV_MIN_SHARE_PCT" 100; then
        record BLOCKED previous_cpu \
            "CPU $NODE0_CPU was only $idle percent idle, so the previous-CPU preference cannot be judged" \
            "$(printf '"start_cpu":%d,"idle_pct":%s' "$NODE0_CPU" "${idle:-0}")"
        return
    fi
    if ! out=$(taskset -c "$NODE0_CPU" "$PREV_PROBE" "$NODE0_CPU" \
        "$PREV_SLEEP_MS" "$PREV_ROUNDS" 2>"$HARNESS_TMP/prev_cpu.err"); then
        record FAIL previous_cpu "the previous-CPU probe failed"
        return
    fi
    hits=$(printf '%s\n' "$out" | grep -oE 'hits=[0-9]+' |
        tail -n 1 | cut -d= -f2 || true)
    rounds=$(printf '%s\n' "$out" | grep -oE 'rounds=[0-9]+' |
        tail -n 1 | cut -d= -f2 || true)
    if [[ -z "$hits" || -z "$rounds" || "$rounds" == "0" ]]; then
        record FAIL previous_cpu "the previous-CPU probe printed no result"
        return
    fi
    share=$(awk -v hits="$hits" -v rounds="$rounds" \
        'BEGIN { printf "%.2f", 100 * hits / rounds }')
    extra=$(printf '"start_cpu":%d,"hits":%s,"rounds":%s,"prev_cpu_share_pct":%s,"idle_pct":%s' \
        "$NODE0_CPU" "$hits" "$rounds" "$share" "${idle:-0}")
    if ! num_in_range "$share" "$PREV_MIN_SHARE_PCT" 100; then
        record FAIL previous_cpu \
            "the woken task returned to CPU $NODE0_CPU in only $hits of $rounds rounds" "$extra"
        return
    fi
    record PASS previous_cpu \
        "the woken task returned to CPU $NODE0_CPU in $hits of $rounds rounds" "$extra"
}

# Section 4.1 orders the local LLC before the local node. The LLC share
# must therefore be at least the node share, and both must reach the gate.
run_llc_before_node() {
    local extra=""

    extra=$(printf '"llc":"%s","llc_share_pct":%s,"node_cpus":"%s","node_share_pct":%s' \
        "$NODE0_LLC" "${LOCAL_LLC_SHARE:-0}" "$NODE0_CPUS" "${LOCAL_NODE_SHARE:-0}")
    if ! num_in_range "$LOCAL_LLC_SHARE" "$LOCALITY_MIN_SHARE_PCT" 100; then
        record FAIL llc_before_node \
            "the local LLC share is below the gate" "$extra"
        return
    fi
    if ! awk -v a="$LOCAL_LLC_SHARE" -v b="$LOCAL_NODE_SHARE" \
        'BEGIN { exit !(a >= b) }'; then
        record FAIL llc_before_node \
            "the local node share is higher than the local LLC share" "$extra"
        return
    fi
    record PASS llc_before_node \
        "the LLC share $LOCAL_LLC_SHARE is at least the node share $LOCAL_NODE_SHARE" "$extra"
}

# One steal case. The mask names the only CPUs a task may use, so exactly one
# steal tier can reach a queued task. Args: tag source_cpu peer_cpu mask
#
# The idle window before the load gives the background level of both
# counters. The guest keeps its own tasks, so a counter never sits still.
# The case therefore compares the load induced rise against that level.
run_steal_case() {
    local -r tag="$1"
    local -r source="$2"
    local -r peer="$3"
    local -r mask="$4"
    local -r want="$5"
    local -r other="$6"
    local llc_before=0
    local node_before=0
    local llc_after=0
    local node_after=0
    local bg_llc_before=0
    local bg_node_before=0
    local bg_llc=0
    local bg_node=0
    local want_delta=0
    local other_delta=0
    local want_excess=0
    local other_excess=0
    local bg_want=0
    local observed=""
    local extra=""

    stop_all_workers
    sleep 1
    wait_for_stat_tick 2 || true
    bg_llc_before=$(stat_value "$SCHED_LOG" llc)
    bg_node_before=$(stat_value "$SCHED_LOG" node)
    sleep "$((DURATION + 1))"
    wait_for_stat_tick 2 || true
    bg_llc=$(( $(stat_value "$SCHED_LOG" llc) - bg_llc_before ))
    bg_node=$(( $(stat_value "$SCHED_LOG" node) - bg_node_before ))

    llc_before=$(stat_value "$SCHED_LOG" llc)
    node_before=$(stat_value "$SCHED_LOG" node)

    # A long task keeps the source CPU busy, so a queued task waits there.
    start_worker "$CG_BURN" "$source" "$HARNESS_TMP/${tag}_source.log" \
        "$WORKLOAD" burn "$((DURATION + 25))" >/dev/null || true
    # A stream of short tasks keeps both CPUs busy and the queues churning.
    start_worker "$CG_BURN" "$mask" "$HARNESS_TMP/${tag}_load.log" \
        "$WORKLOAD" forkexec "$((DURATION + 10))" >/dev/null || true
    sleep 1
    observed=$(observe_cgroup_cpus "$((DURATION + 1))")
    stop_all_workers
    wait_for_stat_tick 3 || true
    llc_after=$(stat_value "$SCHED_LOG" llc)
    node_after=$(stat_value "$SCHED_LOG" node)

    llc_before=${llc_before:-0}
    node_before=${node_before:-0}
    llc_after=${llc_after:-0}
    node_after=${node_after:-0}
    if [[ "$want" == "llc" ]]; then
        want_delta=$(( llc_after - llc_before ))
        other_delta=$(( node_after - node_before ))
        want_excess=$(( want_delta - bg_llc ))
        other_excess=$(( other_delta - bg_node ))
        bg_want=$bg_llc
    else
        want_delta=$(( node_after - node_before ))
        other_delta=$(( llc_after - llc_before ))
        want_excess=$(( want_delta - bg_node ))
        other_excess=$(( other_delta - bg_llc ))
        bg_want=$bg_node
    fi
    if (( other_excess < 0 )); then
        other_excess=0
    fi
    extra=$(printf '"mask":"%s","source_cpu":%d,"peer_cpu":%d,"llc_delta":%d,"node_delta":%d,"llc_background":%d,"node_background":%d,"sampled_cpus":"%s"' \
        "$mask" "$source" "$peer" \
        "$(( llc_after - llc_before ))" "$(( node_after - node_before ))" \
        "$bg_llc" "$bg_node" "${observed:-none}")

    if (( want_excess < 100 )); then
        record FAIL "$tag" "the $want steal counter did not rise above the background" "$extra"
        return
    fi
    if (( other_excess * 4 > want_excess )); then
        record FAIL "$tag" "the $other steal counter rose as well" "$extra"
        return
    fi
    if ! all_cpus_in "$observed" "$mask"; then
        record FAIL "$tag" "a worker ran outside its mask" "$extra"
        return
    fi
    record PASS "$tag" "$want steals $want_delta above a background of $bg_want, $other steals $other_delta" "$extra"
}

run_steal_llc() {
    run_steal_case steal_llc "$NODE0_CPU" "$NODE0_LLC_PEER" "$NODE0_LLC" llc node
}

run_steal_node() {
    run_steal_case steal_node "$NODE0_CPU" "$NODE0_LLC2_PEER" \
        "$NODE0_CPU,$NODE0_LLC2_PEER" node llc
}

# Work runs only on node 1 while node 0 stays idle. An idle CPU of node 0
# must not take work from the other node.
run_no_remote_steal() {
    local observed=""
    local llc_before=0
    local node_before=0
    local llc_after=0
    local node_after=0
    local extra=""

    stop_all_workers
    sleep 1
    wait_for_stat_tick 2 || true
    llc_before=$(stat_value "$SCHED_LOG" llc)
    node_before=$(stat_value "$SCHED_LOG" node)

    start_worker "$CG_BURN" "$NODE1_LLC" "$HARNESS_TMP/remote_load.log" \
        "$WORKLOAD" forkexec "$((DURATION + 10))" >/dev/null || true
    sleep 1
    observed=$(observe_cgroup_cpus "$((DURATION + 1))")
    stop_all_workers
    wait_for_stat_tick 3 || true
    llc_after=$(stat_value "$SCHED_LOG" llc)
    node_after=$(stat_value "$SCHED_LOG" node)

    extra=$(printf '"mask":"%s","node1_cpus":"%s","sampled_cpus":"%s","llc_delta":%d,"node_delta":%d' \
        "$NODE1_LLC" "$NODE1_CPUS" "${observed:-none}" \
        "$(( llc_after - llc_before ))" "$(( node_after - node_before ))")
    if ! all_cpus_in "$observed" "$NODE1_CPUS"; then
        record FAIL no_remote_steal "work from node 1 ran on node 0" "$extra"
        return
    fi
    if [[ "${observed:-none}" == "none" ]]; then
        record FAIL no_remote_steal "no worker was observed" "$extra"
        return
    fi
    record PASS no_remote_steal "node 1 work stayed in node 1" "$extra"
}

# The same boundary with eligible local runnable work present: node 0 has
# unthrottled work of its own, so an idle node 0 CPU has no reason to pull
# node 1 work. The node 1 cgroup must stay on node 1.
run_no_remote_steal_local() {
    local observed=""
    local extra=""

    stop_all_workers
    sleep 1
    if ! start_worker "$CG_BURN" "$NODE0_CPUS" \
        "$HARNESS_TMP/localwork.log" \
        "$WORKLOAD" forkexec "$((DURATION + 12))" >/dev/null; then
        record FAIL no_remote_steal_local "cannot start the local work"
        return
    fi
    if ! start_worker "$CG_NODE1" "$NODE1_CPUS" \
        "$HARNESS_TMP/node1work.log" \
        "$WORKLOAD" forkexec "$((DURATION + 12))" >/dev/null; then
        stop_all_workers
        record FAIL no_remote_steal_local "cannot start the node 1 work"
        return
    fi
    sleep 1
    observed=$(observe_cgroup_cpus_in "$CG_NODE1" "$((DURATION + 1))")
    stop_all_workers
    extra=$(printf '"node0_cpus":"%s","node1_cpus":"%s","node1_sampled_cpus":"%s"' \
        "$NODE0_CPUS" "$NODE1_CPUS" "${observed:-none}")
    if [[ "${observed:-none}" == "none" ]]; then
        record FAIL no_remote_steal_local "no node 1 worker was observed" "$extra"
        return
    fi
    if ! all_cpus_in "$observed" "$NODE1_CPUS"; then
        record FAIL no_remote_steal_local \
            "node 1 work ran on node 0 while eligible local work existed" "$extra"
        return
    fi
    record PASS no_remote_steal_local \
        "node 1 work stayed in node 1 with eligible local work present" "$extra"
}

# The boundary with the local work quota-parked. A parked task is on no
# CPU tree, so it is not local runnable work. Node 1 work must still stay
# in node 1, and the scheduler throttle counter must rise.
run_no_remote_steal_parked() {
    local observed=""
    local th0=0
    local th1=0
    local extra=""

    stop_all_workers
    if ! cgroup_write "$CG_PARKED" cpu.max "1000 100000"; then
        record FAIL no_remote_steal_parked "cannot set cpu.max on the parked cgroup"
        return
    fi
    cgroup_write "$CG_PARKED" cpu.max.burst 0 || true
    sleep 1
    th0=$(stat_value "$SCHED_LOG" throttled)
    if ! start_worker "$CG_PARKED" "$NODE0_CPUS" \
        "$HARNESS_TMP/parkedlocal.log" \
        "$WORKLOAD" burn "$((DURATION + 12))" >/dev/null; then
        record FAIL no_remote_steal_parked "cannot start the parked local work"
        return
    fi
    if ! start_worker "$CG_NODE1" "$NODE1_CPUS" \
        "$HARNESS_TMP/node1parked.log" \
        "$WORKLOAD" forkexec "$((DURATION + 12))" >/dev/null; then
        stop_all_workers
        record FAIL no_remote_steal_parked "cannot start the node 1 work"
        return
    fi
    sleep 1
    observed=$(observe_cgroup_cpus_in "$CG_NODE1" "$((DURATION + 1))")
    th1=$(stat_value "$SCHED_LOG" throttled)
    stop_all_workers
    cgroup_write "$CG_PARKED" cpu.max "max 100000" || true
    extra=$(printf '"node1_cpus":"%s","node1_sampled_cpus":"%s","throttled_before":%s,"throttled_after":%s' \
        "$NODE1_CPUS" "${observed:-none}" "$th0" "$th1")
    if (( th1 <= th0 )); then
        record FAIL no_remote_steal_parked \
            "the local work was not parked: the throttle counter did not rise" "$extra"
        return
    fi
    if [[ "${observed:-none}" == "none" ]] ||
        ! all_cpus_in "$observed" "$NODE1_CPUS"; then
        record FAIL no_remote_steal_parked \
            "node 1 work did not stay in node 1 around parked local work" "$extra"
        return
    fi
    record PASS no_remote_steal_parked \
        "node 1 work stayed in node 1 while local work was parked" "$extra"
}

run_remote_spill() {
    local cpu
    local log=""
    local out_of_mask=""
    local distinct=""
    local first=""
    local extra=""
    local local_idle=0
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
    local_idle=$(max_idle_percent "$NODE0_CPUS" 300)

    if ! log=$(probe_run "$NODE0_CPU" remote_spill all broaden); then
        stop_all_workers
        record FAIL remote_spill "the probe did not complete"
        return
    fi
    stop_all_workers
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    first=$(probe_field "$log" first_cpu)
    extra=$(printf '"start_cpu":%d,"first_cpu":%s,"sampled_cpus":"%s","node0_cpus":"%s","node1_cpus":"%s","out_of_mask":%s,"local_idle_pct":%s' \
        "$NODE0_CPU" "${first:-0}" "${distinct:-none}" "$NODE0_CPUS" \
        "$NODE1_CPUS" "${out_of_mask:-0}" "${local_idle:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]]; then
        record FAIL remote_spill "a sample left the full CPU set" "$extra"
        return
    fi
    if num_in_range "$local_idle" "$LOCAL_IDLE_PCT" 100; then
        record FAIL remote_spill \
            "a local CPU was $local_idle percent idle before the probe, so no remote spill was allowed" "$extra"
        return
    fi
    if all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL remote_spill "a crowded node 0 kept the task, no remote-node spill" "$extra"
        return
    fi
    record PASS remote_spill "the task spilled out of node 0; samples $distinct" "$extra"
}

# The mask keeps the task inside node 0, so a crowded node 0 must not push
# it to node 1.
run_remote_spill_mask() {
    local cpu
    local log=""
    local out_of_mask=""
    local distinct=""
    local extra=""
    local i

    while IFS= read -r cpu; do
        for i in 0 1; do
            if ! start_worker "$CG_BURN" "$cpu" "$HARNESS_TMP/maskburn_${cpu}_${i}.log" \
                timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
                "$WORKLOAD" burn "$((DURATION + 10))" >/dev/null; then
                record FAIL remote_spill_mask "cannot start a local burner"
                stop_all_workers
                return
            fi
        done
    done < <(cpulist_expand "$NODE0_CPUS")
    sleep 1

    if ! log=$(probe_run "$NODE0_CPU" remote_spill_mask "$NODE0_CPUS"); then
        stop_all_workers
        record FAIL remote_spill_mask "the probe did not complete"
        return
    fi
    stop_all_workers
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    extra=$(printf '"mask":"%s","sampled_cpus":"%s","node1_cpus":"%s","out_of_mask":%s' \
        "$NODE0_CPUS" "${distinct:-none}" "$NODE1_CPUS" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]] || ! all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL remote_spill_mask "a task left the mask that forbids node 1" "$extra"
        return
    fi
    record PASS remote_spill_mask "the mask kept the task in node 0" "$extra"
}

# Quota-parked local work is not runnable. The local CPUs are therefore
# idle even though the cgroup has busy workers. A new task must run on a
# local CPU, not spill to node 1. The throttle counter proves the work was
# parked rather than merely light.
run_remote_spill_parked() {
    local cpu=""
    local log=""
    local out_of_mask=""
    local distinct=""
    local extra=""
    local th0=0
    local th1=0
    local local_idle=0

    stop_all_workers
    if ! cgroup_write "$CG_PARKED" cpu.max "1000 100000"; then
        record FAIL remote_spill_parked "cannot set cpu.max on the parked cgroup"
        return
    fi
    cgroup_write "$CG_PARKED" cpu.max.burst 0 || true
    sleep 1
    th0=$(stat_value "$SCHED_LOG" throttled)
    while IFS= read -r cpu; do
        if ! start_worker "$CG_PARKED" "$cpu" "$HARNESS_TMP/parked_${cpu}.log" \
            timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
            "$WORKLOAD" burn "$((DURATION + 10))" >/dev/null; then
            record FAIL remote_spill_parked "cannot start a parked burner"
            stop_all_workers
            return
        fi
    done < <(cpulist_expand "$NODE0_CPUS")
    sleep 1
    local_idle=$(max_idle_percent "$NODE0_CPUS" 300)
    if ! log=$(probe_run "$NODE0_CPU" remote_spill_parked all broaden); then
        stop_all_workers
        record FAIL remote_spill_parked "the probe did not complete"
        return
    fi
    th1=$(stat_value "$SCHED_LOG" throttled)
    stop_all_workers
    cgroup_write "$CG_PARKED" cpu.max "max 100000" || true
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    extra=$(printf '"start_cpu":%d,"sampled_cpus":"%s","node0_cpus":"%s","out_of_mask":%s,"local_idle_pct":%s,"throttled_before":%s,"throttled_after":%s' \
        "$NODE0_CPU" "${distinct:-none}" "$NODE0_CPUS" "${out_of_mask:-0}" \
        "${local_idle:-0}" "$th0" "$th1")
    if (( th1 <= th0 )); then
        record FAIL remote_spill_parked \
            "the local work was not parked: the throttle counter did not rise" "$extra"
        return
    fi
    if [[ "${out_of_mask:-1}" != "0" ]]; then
        record FAIL remote_spill_parked "a sample left the full CPU set" "$extra"
        return
    fi
    if ! num_in_range "$local_idle" "$LOCAL_IDLE_PCT" 100; then
        record FAIL remote_spill_parked \
            "the parked work kept the local CPUs busy, so the case did not test an idle local CPU" "$extra"
        return
    fi
    if ! all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL remote_spill_parked \
            "a task spilled to node 1 while a local CPU was idle and the local work was parked" "$extra"
        return
    fi
    record PASS remote_spill_parked \
        "the task stayed in node 0 while parked work held no local CPU" "$extra"
}

# Affinity-ineligible local work. One local CPU is pinned busy and the
# other local CPU is idle. The probe can run on the idle local CPU, so a
# remote sample is a placement failure.
run_remote_spill_affinity() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local extra=""
    local local_idle=0

    stop_all_workers
    sleep 1
    if ! start_worker "$CG_BURN" "$NODE0_CPU" "$HARNESS_TMP/pinned_local.log" \
        timeout --signal=TERM --kill-after=5s "$((DURATION + 20))s" \
        "$WORKLOAD" burn "$((DURATION + 10))" >/dev/null; then
        record FAIL remote_spill_affinity "cannot start the pinned local burner"
        return
    fi
    sleep 1
    local_idle=$(max_idle_percent "$NODE0_CPUS" 300)
    if ! log=$(probe_run "$NODE0_CPU" remote_spill_affinity all broaden); then
        stop_all_workers
        record FAIL remote_spill_affinity "the probe did not complete"
        return
    fi
    stop_all_workers
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    extra=$(printf '"start_cpu":%d,"sampled_cpus":"%s","node0_cpus":"%s","out_of_mask":%s,"local_idle_pct":%s' \
        "$NODE0_CPU" "${distinct:-none}" "$NODE0_CPUS" "${out_of_mask:-0}" \
        "${local_idle:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]]; then
        record FAIL remote_spill_affinity "a sample left the full CPU set" "$extra"
        return
    fi
    if ! num_in_range "$local_idle" "$LOCAL_IDLE_PCT" 100; then
        record FAIL remote_spill_affinity \
            "no local CPU was idle, so the case did not test an ineligible local task" "$extra"
        return
    fi
    if ! all_cpus_in "$distinct" "$NODE0_CPUS"; then
        record FAIL remote_spill_affinity \
            "a task spilled to node 1 while an affinity-allowed local CPU was idle" "$extra"
        return
    fi
    record PASS remote_spill_affinity \
        "the task used the idle local CPU, not node 1" "$extra"
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

# Move a busy task from node 0 to node 1 and check that it keeps running.
run_migration() {
    local pid=""
    local cpu_before=""
    local cpu_after=""
    local time_before=0
    local time_after=0
    local moved=0
    local extra=""
    local i

    stop_all_workers
    start_worker "$CG_BURN" "$NODE0_CPU" "$HARNESS_TMP/migrate.log" \
        "$WORKLOAD" burn "$((DURATION + 25))" >/dev/null || true
    pid="${HARNESS_LAST_PID:-}"
    if [[ -z "$pid" || ! -r "/proc/$pid/stat" ]]; then
        record FAIL migration "the busy task did not start"
        stop_all_workers
        return
    fi
    sleep 1
    cpu_before=$(worker_cpu "$pid" 2>/dev/null || true)
    time_before=$(worker_cpu_time "$pid" 2>/dev/null || echo 0)

    if ! taskset -cp "$NODE1_CPUS" "$pid" >"$HARNESS_TMP/migrate_taskset.log" 2>&1; then
        record FAIL migration "cannot change the affinity of the task"
        stop_all_workers
        return
    fi

    for (( i = 0; i < 100; i++ )); do
        cpu_after=$(worker_cpu "$pid" 2>/dev/null || true)
        if [[ -n "$cpu_after" ]] && cpu_in_list "$cpu_after" "$NODE1_CPUS"; then
            moved=1
            break
        fi
        sleep 0.1
    done
    # The task needs a slice on the new CPU before it burns again.
    sleep 1
    time_after=$(worker_cpu_time "$pid" 2>/dev/null || echo 0)
    extra=$(printf '"pid":%s,"cpu_before":%s,"cpu_after":%s,"node0_cpus":"%s","node1_cpus":"%s","cpu_ticks_before":%s,"cpu_ticks_after":%s' \
        "$pid" "${cpu_before:-none}" "${cpu_after:-none}" "$NODE0_CPUS" "$NODE1_CPUS" \
        "$time_before" "$time_after")
    stop_all_workers

    if (( moved == 0 )); then
        record FAIL migration "the task did not move to node 1" "$extra"
        return
    fi
    if (( time_after <= time_before )); then
        record FAIL migration "the task stopped making progress after the move" "$extra"
        return
    fi
    record PASS migration "the task moved to node 1 and kept running" "$extra"
}

# One named case, for a focused rerun. The full gate runs every case.
run_named_case() {
    case "$1" in
        previous_cpu) run_previous_cpu ;;
        local_llc) run_local_llc ;;
        local_node) run_local_node ;;
        llc_before_node) run_llc_before_node ;;
        steal_llc) run_steal_llc ;;
        steal_node) run_steal_node ;;
        no_remote_steal) run_no_remote_steal ;;
        no_remote_steal_local) run_no_remote_steal_local ;;
        no_remote_steal_parked) run_no_remote_steal_parked ;;
        remote_spill) run_remote_spill ;;
        remote_spill_mask) run_remote_spill_mask ;;
        remote_spill_parked) run_remote_spill_parked ;;
        remote_spill_affinity) run_remote_spill_affinity ;;
        affinity) run_affinity ;;
        affinity_one) run_affinity_one ;;
        migration) run_migration ;;
        *)
            record BLOCKED "case:$1" "unknown --case name"
            return 1
            ;;
    esac
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
    rmdir -- "$CG_BURN" "$CG_NODE1" "$CG_PARKED" "$CGROUP_PARENT" 2>/dev/null || true
    if [[ ! -e "$CG_BURN" && ! -e "$CG_NODE1" && ! -e "$CG_PARKED" &&
        ! -e "$CGROUP_PARENT" ]]; then
        record PASS cgroup_cleanup "the burn cgroups were removed"
    else
        record FAIL cgroup_cleanup "a burn cgroup remains"
    fi
}

main() {
    harness_init numa_placement
    mkdir -p "$HARNESS_TMP/config/scx_infinity"
    export XDG_CONFIG_HOME="$HARNESS_TMP/config"
    # A short statistics period gives the steal counters a usable resolution.
    printf 'stats_interval_ms = 250\n' >"$XDG_CONFIG_HOME/scx_infinity/config.toml"
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
    if ! require_scheduler_identity; then
        exit 2
    fi

    if [[ -n "$CASE" ]]; then
        run_named_case "$CASE"
        check_alive "$CASE" || exit 1
        teardown
        if [[ -n "$OUT" ]]; then
            cp -- "$SCHED_LOG" "$OUT.scheduler.log" 2>/dev/null || true
        fi
        return
    fi

    run_previous_cpu
    check_alive previous_cpu || exit 1
    run_local_llc
    check_alive local_llc || exit 1
    run_local_node
    check_alive local_node || exit 1
    run_llc_before_node
    run_steal_llc
    check_alive steal_llc || exit 1
    run_steal_node
    check_alive steal_node || exit 1
    run_no_remote_steal
    check_alive no_remote_steal || exit 1
    run_no_remote_steal_local
    check_alive no_remote_steal_local || exit 1
    run_no_remote_steal_parked
    check_alive no_remote_steal_parked || exit 1
    run_remote_spill
    check_alive remote_spill || exit 1
    run_remote_spill_mask
    check_alive remote_spill_mask || exit 1
    run_remote_spill_parked
    check_alive remote_spill_parked || exit 1
    run_remote_spill_affinity
    check_alive remote_spill_affinity || exit 1
    run_affinity
    check_alive affinity || exit 1
    run_affinity_one
    check_alive affinity_one || exit 1
    run_migration
    check_alive migration || exit 1
    teardown
    if [[ -n "$OUT" ]]; then
        cp -- "$SCHED_LOG" "$OUT.scheduler.log" 2>/dev/null || true
    fi
}

main "$@"
