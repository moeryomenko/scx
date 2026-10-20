#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_numa_placement.sh - two-node vNUMA placement harness.
#
# The harness loads scx_infinity in a guest with two vNUMA nodes and checks:
#
#   local_llc        a task woken on an idle CPU stays inside that LLC
#   local_node       a task woken on an idle CPU stays inside that NUMA node
#   steal_llc        a peer inside the same LLC steals, and only the LLC tier
#                    counter moves
#   steal_node       a peer inside the same node but in another LLC steals, and
#                    only the node tier counter moves
#   no_remote_steal  an idle node does not take work from the other node
#   remote_spill     with the local node saturated, a new task is placed on the
#                    remote node at wakeup
#   remote_spill_mask the mask forbids the remote node, so no spill happens
#   affinity         a task that narrows its mask never runs outside the mask
#   affinity_one     a task narrowed to one CPU never runs on another CPU
#   migration        a task moved to the other node keeps running there
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
NODE0_LLC_PEER=""
NODE0_LLC2=""
NODE0_LLC2_CPU=""
NODE0_LLC2_PEER=""
NODE1_LLC=""
DMESG_BASELINE=0

# The lowest share of the probe samples that must stay in the local LLC or
# the local node. The guest keeps its own tasks, so a wakeup can find the
# local cache busy and move to another core of the same node. That is the
# placement order of specification section 4.1, so the case measures the
# preference over the whole sample window instead of demanding that no
# sample ever leaves the domain.
LOCALITY_MIN_SHARE_PCT=${LOCALITY_MIN_SHARE_PCT:-90}

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

# Poll every task of the harness cgroup and print every CPU one of them ran
# on. The children of a workload inherit the cgroup, so this covers the
# whole load and not only the process the harness started.
observe_cgroup_cpus() {
    local -r seconds="$1"
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
        done <"$CG_BURN/cgroup.procs" 2>/dev/null || true
        sleep 0.05
    done
    printf '%s\n' "${seen#,}"
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

run_local_llc() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local first=""
    local share=""
    local extra=""

    if ! log=$(probe_run "$NODE0_CPU" local_llc all broaden); then
        record FAIL local_llc "the probe did not complete"
        return
    fi
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    first=$(probe_field "$log" first_cpu)
    share=$(probe_share "$log" "$NODE0_LLC")
    extra=$(printf '"start_cpu":%d,"first_cpu":%s,"llc":"%s","sampled_cpus":"%s","llc_share_pct":%s,"out_of_mask":%s' \
        "$NODE0_CPU" "${first:-0}" "$NODE0_LLC" "${distinct:-none}" "${share:-0}" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]]; then
        record FAIL local_llc "a sample ran outside the allowed CPU set" "$extra"
        return
    fi
    if ! num_in_range "$share" "$LOCALITY_MIN_SHARE_PCT" 100; then
        record FAIL local_llc "the task left its local LLC $NODE0_LLC" "$extra"
        return
    fi
    record PASS local_llc "$share percent of the samples stayed in LLC $NODE0_LLC" "$extra"
}

run_local_node() {
    local log=""
    local out_of_mask=""
    local distinct=""
    local first=""
    local share=""
    local extra=""

    if ! log=$(probe_run "$NODE0_CPU" local_node all broaden); then
        record FAIL local_node "the probe did not complete"
        return
    fi
    out_of_mask=$(probe_field "$log" out_of_mask)
    distinct=$(probe_field "$log" distinct)
    first=$(probe_field "$log" first_cpu)
    share=$(probe_share "$log" "$NODE0_CPUS")
    extra=$(printf '"start_cpu":%d,"first_cpu":%s,"node_cpus":"%s","sampled_cpus":"%s","node_share_pct":%s,"out_of_mask":%s' \
        "$NODE0_CPU" "${first:-0}" "$NODE0_CPUS" "${distinct:-none}" "${share:-0}" "${out_of_mask:-0}")
    if [[ "${out_of_mask:-1}" != "0" ]]; then
        record FAIL local_node "a sample ran outside the allowed CPU set" "$extra"
        return
    fi
    if ! num_in_range "$share" "$LOCALITY_MIN_SHARE_PCT" 100; then
        record FAIL local_node "the task left its local NUMA node" "$extra"
        return
    fi
    record PASS local_node "$share percent of the samples stayed in node 0" "$extra"
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

    run_local_llc
    check_alive local_llc
    run_local_node
    check_alive local_node
    run_steal_llc
    check_alive steal_llc
    run_steal_node
    check_alive steal_node
    run_no_remote_steal
    check_alive no_remote_steal
    run_remote_spill
    check_alive remote_spill
    run_remote_spill_mask
    check_alive remote_spill_mask
    run_affinity
    check_alive affinity
    run_affinity_one
    check_alive affinity_one
    run_migration
    check_alive migration
    teardown
    if [[ -n "$OUT" ]]; then
        cp -- "$SCHED_LOG" "$OUT.scheduler.log" 2>/dev/null || true
    fi
}

main "$@"
