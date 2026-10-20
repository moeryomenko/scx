#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_cgroup_harness.sh - cgroup v2 behavior harness for scx_infinity.
#
# The harness loads scx_infinity in a disposable guest and runs the cgroup
# cases of specification revision 4, section 7.4 and 7.5. Every case pins
# its workers to one CPU, except the shared-quota case, which pins its two
# workers to two CPUs, and the move-conservation case, which saturates two
# CPUs. The ratio, idle and quota checks need contention on one CPU.
#
# Cases, one JSON record per case per trial:
#
#   weight_ratio          A-01  cpu.weight 100:200, ratio 1.8 to 2.2
#   live_weight           A-02  100:100 then 100:200, second window 1.8 to 2.2
#   nested_weight         A-03  nested 100:200 siblings, ratio 1.8 to 2.2
#   threaded_fixture      A-04  domain threaded parent, two direct tasks and
#                               one threaded child, each 0.8 to 1.25 of a third
#   unequal_populations   A-05  four workers against one, 45 to 55 percent each,
#                               per-task share within 10 percent
#   ancestor_reweight     A-06  ancestor 100 to 200 live, subtree 1.8 to 2.2 and
#                               the internal 1:2 split 1.8 to 2.2
#   cpu_idle_group        A-07  cpu.idle=1 group against weight 100, 2 to 4 percent
#   sched_idle_task       A-08  SCHED_IDLE task against a normal task, 2 to 4
#   idle_off_equal        A-09  two equal groups, 45 to 55 percent each
#   idle_both_levels      A-10  idle group with one SCHED_IDLE task, 0.06 to
#                               0.11 percent over five 120 second trials
#   idle_wakeup           A-11  the idle task runs within 10 ms after the
#                               normal worker stops
#   cpu_max               A-12  50000/100000 at 45 to 55 percent with a rising
#                               scheduler throttle counter
#   ledger_yield          A-13  yield-heavy ledger, actual runtime only, the
#                               per-task sum matches cpu.stat within 2 percent
#   quota_nested          A-14  parent 60 percent, child 50 percent weight 1000
#                               against an unlimited weight-100 sibling
#   quota_shared          A-15  shared 100 percent quota on two CPUs, 90 to
#                               110 percent of one CPU
#   quota_live            A-16  live quota change settles in one period plus
#                               one tick
#   move_conservation     A-17  old-path and new-path ledgers sum to the task
#                               runtime within one accounting tick
#   cpu_max_burst         A-18  500 ms credit, 300 ms sample above the matched
#                               zero-burst control, 5 s drain, 10 s steady
#
# The harness fails closed. It refuses to run without a disposable VM
# (SCX_INFINITY_VM=1), root, a threaded cgroup fixture and the cgroup
# files. A missing precondition is BLOCKED, never PASS. A case that cannot
# read its counters is FAIL, and a case that cannot set up its fixture is
# BLOCKED.
#
# Usage:
#   SCX_INFINITY_VM=1 sudo \
#     scheds/experimental/scx_infinity/scripts/infinity_cgroup_harness.sh \
#     [--trials N] [--cpu N] [--cpu2 N] [--window SEC] [--settle SEC] \
#     [--idle-sec SEC] [--scheduler PATH] [--out FILE] [--check] [--keep]
#
# Output: one JSON object per line on stdout. The last line is the summary.
# Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED.
#
# The case checks the policy against the run range. A FAIL from the current
# tree means the scheduler does not implement the revision-4 rule yet, not
# that the harness case is missing.

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=infinity_harness_lib.sh
. "$SCRIPT_DIR/infinity_harness_lib.sh"
# shellcheck source=infinity_cgroup_lib.sh
. "$SCRIPT_DIR/infinity_cgroup_lib.sh"

TRIALS=5
CPU=0
CPU2=1
WINDOW=5
SETTLE=1
IDLE_SEC=120
SCHED_BIN=""
CHECK_ONLY=0
KEEP=0
OUT=""
CGROUP_PARENT=""
SCHED_LOG=""
WORKLOAD=""
THREADED_WORKER=""
DMESG_BASELINE=0

# Median inputs. One array per case family.
WEIGHT_RATIOS=()
LIVE_RATIOS=()
NESTED_RATIOS=()
THREADED_RATIOS=()
UNEQUAL_SHARES=()
ANCESTOR_RATIOS=()
IDLE_GROUP_SHARES=()
SCHED_IDLE_SHARES=()
IDLE_OFF_SHARES=()
IDLE_BOTH_SHARES=()
IDLE_LATENCIES=()
CPU_MAX_RATES=()
LEDGER_DEVIATIONS=()
QUOTA_NESTED_RATES=()
QUOTA_SHARED_RATES=()
QUOTA_LIVE_RATES=()
MOVE_ERRORS=()
BURST_RATIOS=()
BURST_CONTROLS=()
BURST_GAPS=()

usage() {
    cat >&2 <<'EOF'
usage: infinity_cgroup_harness.sh [--trials N] [--cpu N] [--cpu2 N]
       [--window SEC] [--settle SEC] [--idle-sec SEC] [--scheduler PATH]
       [--out FILE] [--check] [--keep]

  --trials N        number of trials per case, default 5
  --cpu N           CPU that the one-CPU cases are pinned to, default 0
  --cpu2 N          second CPU for the shared-quota case, default 1
  --window SEC      measurement window per case, default 5
  --settle SEC      wait after workers start, default 1
  --idle-sec SEC    length of one both-idle-levels trial, default 120
  --scheduler PATH  scx_infinity binary, default SCX_INFINITY_BIN or target/
  --out FILE        also append the JSON Lines records to FILE
  --check           verify preconditions only, start nothing
  --keep            keep the parent cgroup for inspection after the run
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
        --cpu2)
            CPU2=${2:?}
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
        --idle-sec)
            IDLE_SEC=${2:?}
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
        "$CPU2" =~ ^[0-9]+$ && "$WINDOW" =~ ^[1-9][0-9]*$ &&
        "$SETTLE" =~ ^[0-9]+$ && "$IDLE_SEC" =~ ^[1-9][0-9]*$ ]]; then
    printf 'numeric arguments are invalid\n' >&2
    exit 2
fi
if [[ "$CPU" == "$CPU2" ]]; then
    printf '--cpu and --cpu2 must differ\n' >&2
    exit 2
fi

# ---------------------------------------------------------------------
# Preconditions.
# ---------------------------------------------------------------------

prepare_workload() {
    local source="$SCRIPT_DIR/infinity_workload.c"
    local cc_log="$HARNESS_TMP/cc.log"
    local thread_source="$HARNESS_TMP/infinity_threaded_worker.c"

    require_file "$source" || return 1
    WORKLOAD="$HARNESS_TMP/infinity_workload"
    if ! cc -O2 -Wall -Wextra -o "$WORKLOAD" "$source" 2>"$cc_log"; then
        record FAIL workload_build "cc failed: $(tail -n 3 "$cc_log" 2>/dev/null || true)"
        return 1
    fi
    record PASS workload_build "compiled $source"

    # The A-04 fixture needs one task inside a threaded child cgroup. A
    # thread-group leader cannot enter a threaded subtree, so only a
    # non-leader thread can be moved there, as section 7.8 step 4 and
    # .agent/tasks/feasibility-v4/evidence.md show. This helper keeps the
    # process leader and two spinning threads in the domain parent and
    # moves the third spinning thread into the threaded child.
    cat >"$thread_source" <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct thread_arg {
	const char *child_cg;
	const char *state_path;
	int cpu;
	int seconds;
	int move;
};

static int write_str(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_APPEND);

	if (fd < 0)
		return -1;
	if (write(fd, value, strlen(value)) != (ssize_t)strlen(value)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void *spin(void *arg)
{
	struct thread_arg *a = arg;
	cpu_set_t set;
	char tid[32];
	struct timespec start, now;
	long id;

	CPU_ZERO(&set);
	CPU_SET(a->cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0) {
		perror("sched_setaffinity");
		exit(1);
	}
	id = syscall(SYS_gettid);
	snprintf(tid, sizeof(tid), "%ld\n", id);
	if (write_str(a->state_path, tid) != 0) {
		perror("state file");
		exit(1);
	}
	if (a->move) {
		char path[512];
		char value[32];

		snprintf(path, sizeof(path), "%s/cgroup.threads", a->child_cg);
		snprintf(value, sizeof(value), "%ld\n", id);
		if (write_str(path, value) != 0) {
			perror("cgroup.threads");
			exit(1);
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while ((now.tv_sec - start.tv_sec) < a->seconds);
	return NULL;
}

int main(int argc, char **argv)
{
	struct thread_arg args[3];
	pthread_t threads[3];
	char pid[32];
	char path[512];
	int i;

	if (argc != 6) {
		fprintf(stderr,
			"usage: %s PARENT_CG CHILD_CG CPU SECONDS STATE_FILE\n",
			argv[0]);
		return 2;
	}
	snprintf(path, sizeof(path), "%s/cgroup.procs", argv[1]);
	snprintf(pid, sizeof(pid), "%d\n", getpid());
	if (write_str(path, pid) != 0) {
		perror("cgroup.procs");
		return 1;
	}
	for (i = 0; i < 3; i++) {
		args[i].child_cg = argv[2];
		args[i].state_path = argv[5];
		args[i].cpu = atoi(argv[3]);
		args[i].seconds = atoi(argv[4]);
		args[i].move = (i == 2);
		if (pthread_create(&threads[i], NULL, spin, &args[i]) != 0) {
			fprintf(stderr, "pthread_create failed\n");
			return 1;
		}
	}
	for (i = 0; i < 3; i++)
		pthread_join(threads[i], NULL);
	printf("done=1\n");
	return 0;
}
EOF
    THREADED_WORKER="$HARNESS_TMP/infinity_threaded_worker"
    if ! cc -O2 -Wall -Wextra -pthread -o "$THREADED_WORKER" "$thread_source" 2>"$cc_log"; then
        record FAIL workload_build "cc failed for the threaded worker: $(tail -n 3 "$cc_log" 2>/dev/null || true)"
        return 1
    fi
    record PASS threaded_worker_build "compiled the A-04 threaded worker"
}

# The threaded fixture needs a domain threaded parent that holds direct
# tasks and threaded children at the same time. The probe proves the
# kernel accepts the type writes before a case depends on them.
require_cgroup_threaded() {
    local root=""
    local probe=""
    local child=""
    local parent_type=""
    local child_type=""

    if ! root=$(cgroup2_root); then
        record BLOCKED cgroup_threaded "no cgroup v2 mount"
        return 1
    fi
    probe="$root/scx-infinity-thread-probe.$$"
    child="$probe/child"
    if ! mkdir -- "$probe" 2>/dev/null; then
        record BLOCKED cgroup_threaded "cannot create $probe"
        return 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$probe") 2>/dev/null || true"
    cleanup_push "rmdir -- $(printf '%q' "$child") 2>/dev/null || true"
    if ! cgroup_enable_cpu_at "$probe"; then
        record BLOCKED cgroup_threaded "cannot enable the cpu controller in $probe"
        return 1
    fi
    if ! mkdir -- "$child" 2>/dev/null; then
        record BLOCKED cgroup_threaded "cannot create $child"
        return 1
    fi
    if ! printf 'threaded\n' >"$child/cgroup.type" 2>/dev/null; then
        record BLOCKED cgroup_threaded "cannot set $child/cgroup.type to threaded"
        return 1
    fi
    parent_type=$(cat "$probe/cgroup.type" 2>/dev/null || true)
    child_type=$(cat "$child/cgroup.type" 2>/dev/null || true)
    if [[ "$child_type" != "threaded" ]]; then
        record BLOCKED cgroup_threaded "child type is '$child_type', expected 'threaded'"
        return 1
    fi
    if [[ "$parent_type" != "domain threaded" ]]; then
        record BLOCKED cgroup_threaded "parent type is '$parent_type', expected 'domain threaded'"
        return 1
    fi
    rmdir -- "$child" "$probe" 2>/dev/null || true
    record PASS cgroup_threaded "domain threaded parent and threaded child"
}

# cpu.idle must be writable and readable. The weight of an idle group is
# 3, so a missing write makes every idle case meaningless.
require_cgroup_idle() {
    local root=""
    local probe=""
    local value=""

    if ! root=$(cgroup2_root); then
        record BLOCKED cgroup_idle "no cgroup v2 mount"
        return 1
    fi
    probe="$root/scx-infinity-idle-probe.$$"
    if ! mkdir -- "$probe" 2>/dev/null; then
        record BLOCKED cgroup_idle "cannot create $probe"
        return 1
    fi
    cleanup_push "rmdir -- $(printf '%q' "$probe") 2>/dev/null || true"
    if ! printf '1\n' >"$probe/cpu.idle" 2>/dev/null; then
        record BLOCKED cgroup_idle "cpu.idle is not writable"
        return 1
    fi
    value=$(cat "$probe/cpu.idle" 2>/dev/null || true)
    if [[ "$value" != "1" ]]; then
        record BLOCKED cgroup_idle "cpu.idle reads '$value' after writing 1"
        return 1
    fi
    if ! printf '0\n' >"$probe/cpu.idle" 2>/dev/null; then
        record BLOCKED cgroup_idle "cpu.idle cannot be cleared"
        return 1
    fi
    rmdir -- "$probe" 2>/dev/null || true
    record PASS cgroup_idle "cpu.idle is writable and reads back"
}

require_proc_schedstat() {
    if [[ ! -r /proc/self/schedstat ]]; then
        record BLOCKED proc_schedstat "/proc/PID/schedstat is missing"
        return 1
    fi
    record PASS proc_schedstat "/proc/PID/schedstat is readable"
}

require_two_cpus() {
    local online=""
    local count=0

    online=$(cat /sys/devices/system/cpu/online 2>/dev/null || true)
    if [[ -z "$online" ]]; then
        record BLOCKED cpu_count "the online CPU list is missing"
        return 1
    fi
    count=$(cpulist_count "$online")
    if (( count < 2 )); then
        record BLOCKED cpu_count "only $count CPU online; the quota and move cases need two"
        return 1
    fi
    if ! cpu_in_list "$CPU" "$online"; then
        record BLOCKED cpu_count "CPU $CPU is not online ($online)"
        return 1
    fi
    if ! cpu_in_list "$CPU2" "$online"; then
        record BLOCKED cpu_count "CPU $CPU2 is not online ($online)"
        return 1
    fi
    record PASS cpu_count "online=$online"
}

preflight() {
    local missing=0
    local state=""

    require_disposable_vm || missing=1
    require_root || missing=1
    require_two_cpus || missing=1
    require_cgroup_cpu || missing=1
    require_cgroup_threaded || missing=1
    require_cgroup_idle || missing=1
    require_proc_schedstat || missing=1
    require_cmd cc || missing=1
    require_cmd taskset || missing=1
    require_cmd chrt || missing=1
    require_cmd timeout || missing=1
    require_cmd find || missing=1
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

# ---------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------

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
    if (( KEEP )); then
        note cgroup "keep requested; groups at $CGROUP_PARENT"
    fi
}

# Create a case root and report failure in the case check. The cpu
# controller is enabled for the case root's children, so a leaf group
# created below it has the cpu.weight, cpu.idle and cpu.max files.
case_root() {
    local -r check="$1"
    local -r name="$2"
    local dir=""
    local current=""

    if ! dir=$(cg_case_root "$name"); then
        record FAIL "$check" "cannot create the case tree $name"
        return 1
    fi
    if ! cg_enable_subtree "$dir"; then
        record FAIL "$check" "cannot enable the cpu controller in the case tree $name"
        cg_remove_tree "$dir"
        return 1
    fi
    current=$(<"$dir/cgroup.subtree_control") || current=""
    if [[ " $current " != *" cpu "* ]]; then
        record FAIL "$check" "the cpu controller is not listed in the case tree $name after the write"
        cg_remove_tree "$dir"
        return 1
    fi
    printf '%s\n' "$dir"
}

# Stop the workers of one case and remove its tree.
case_done() {
    local -r dir="$1"

    stop_all_workers
    if ! cg_remove_tree "$dir"; then
        record FAIL case_cleanup "cannot remove the case tree $dir"
    fi
}

# ---------------------------------------------------------------------
# Workers and measurements.
# ---------------------------------------------------------------------

start_burn() {
    local -r cg="$1"
    local -r tag="$2"
    local -r log="$HARNESS_TMP/${tag}.log"

    start_worker "$cg" "$CPU" "$log" "$WORKLOAD" burn 3600 >/dev/null
}

start_burn_on() {
    local -r cg="$1"
    local -r cpu="$2"
    local -r tag="$3"
    local -r log="$HARNESS_TMP/${tag}.log"

    start_worker "$cg" "$cpu" "$log" "$WORKLOAD" burn 3600 >/dev/null
}

# A SCHED_IDLE task has weight 3 in the scheduler. chrt sets the policy
# before the workload runs.
start_idle_burn() {
    local -r cg="$1"
    local -r tag="$2"
    local -r log="$HARNESS_TMP/${tag}.log"

    start_worker "$cg" "$CPU" "$log" chrt -i 0 "$WORKLOAD" burn 3600 >/dev/null
}

start_sleeper() {
    local -r cg="$1"
    local -r tag="$2"
    local -r log="$HARNESS_TMP/${tag}.log"

    start_worker "$cg" "$CPU" "$log" "$WORKLOAD" sleeper 3600 >/dev/null
}

# Print the two usage_usec deltas of two groups over one window.
measure_pair() {
    local -r cg_a="$1"
    local -r cg_b="$2"
    local -r seconds="$3"
    local a0=""
    local b0=""
    local a1=""
    local b1=""

    a0=$(cg_usage_us "$cg_a") || return 1
    b0=$(cg_usage_us "$cg_b") || return 1
    sleep "$seconds"
    a1=$(cg_usage_us "$cg_a") || return 1
    b1=$(cg_usage_us "$cg_b") || return 1
    printf '%s %s\n' "$((a1 - a0))" "$((b1 - b0))"
}

# Print one group's usage_usec delta over one window.
measure_group() {
    local -r cg="$1"
    local -r seconds="$2"
    local before=""
    local after=""

    before=$(cg_usage_us "$cg") || return 1
    sleep "$seconds"
    after=$(cg_usage_us "$cg") || return 1
    printf '%s\n' "$((after - before))"
}

# Print the runtime_us delta of one task over one window.
measure_task() {
    local -r pid="$1"
    local -r seconds="$2"
    local before=""
    local after=""

    before=$(cg_task_runtime_us "$pid") || return 1
    sleep "$seconds"
    after=$(cg_task_runtime_us "$pid") || return 1
    printf '%s\n' "$((after - before))"
}

# Print the value of WANT from a "pid value" table.
table_value() {
    local -r table="$1"
    local -r want="$2"
    local pid=""
    local value=""

    while IFS=' ' read -r pid value; do
        if [[ "$pid" == "$want" ]]; then
            printf '%s\n' "$value"
            return 0
        fi
    done <<<"$table"
    return 1
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

sched_counter() {
    stat_value "$SCHED_LOG" "$1"
}

has_stats_line() {
    [[ -n "$(stats_line "$SCHED_LOG")" ]]
}

# ---------------------------------------------------------------------
# A-01 startup weight.
# ---------------------------------------------------------------------

run_weight_trial() {
    local -r trial="$1"
    local dir=""
    local a=""
    local b=""
    local pair=""
    local ua=0
    local ub=0
    local ratio=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root weight_ratio weight); then
        return 0
    fi
    if ! a=$(cg_group "$dir" a) || ! b=$(cg_group "$dir" b); then
        record FAIL weight_ratio "trial $trial cannot create the worker groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 100 || ! cg_weight "$b" 200; then
        record FAIL weight_ratio "trial $trial cannot write cpu.weight"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$a" weight_a || ! start_burn "$b" weight_b; then
        record FAIL weight_ratio "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL weight_ratio "trial $trial cannot read cpu.stat usage_usec"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health weight_ratio; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" ua ub
    ratio=$(fp_ratio "$ua" "$ub")
    if num_in_range "$ratio" 1.8 2.2; then
        status=PASS
    fi
    WEIGHT_RATIOS+=("$ratio")
    extra=$(printf '"trial":%d,"a_usec":%s,"b_usec":%s,"ratio":%s,"expected":"1.8-2.2"' \
        "$trial" "$ua" "$ub" "$ratio")
    record "$status" weight_ratio \
        "trial $trial weight 100:200 ratio $ratio, expected 1.8 to 2.2" "$extra"
}

# ---------------------------------------------------------------------
# A-02 live weight change.
# ---------------------------------------------------------------------

run_live_trial() {
    local -r trial="$1"
    local dir=""
    local a=""
    local b=""
    local pair1=""
    local pair2=""
    local a1=0
    local b1=0
    local a2=0
    local b2=0
    local ratio1=""
    local ratio2=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root live_weight live); then
        return 0
    fi
    if ! a=$(cg_group "$dir" a) || ! b=$(cg_group "$dir" b); then
        record FAIL live_weight "trial $trial cannot create the worker groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 100 || ! cg_weight "$b" 100; then
        record FAIL live_weight "trial $trial cannot write the starting weights"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$a" live_a || ! start_burn "$b" live_b; then
        record FAIL live_weight "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair1=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL live_weight "trial $trial cannot read the first window"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$b" 200; then
        record FAIL live_weight "trial $trial cannot change the live weight"
        case_done "$dir"
        return 0
    fi
    sleep 0.2
    if ! pair2=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL live_weight "trial $trial cannot read the second window"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health live_weight; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair1" a1 b1
    read_pair "$pair2" a2 b2
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

# ---------------------------------------------------------------------
# A-03 nested 100:200 siblings.
# ---------------------------------------------------------------------

run_nested_trial() {
    local -r trial="$1"
    local dir=""
    local parent=""
    local a=""
    local b=""
    local pair=""
    local ua=0
    local ub=0
    local ratio=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root nested_weight nested); then
        return 0
    fi
    if ! parent=$(cg_group "$dir" parent); then
        record FAIL nested_weight "trial $trial cannot create the parent group"
        case_done "$dir"
        return 0
    fi
    if ! cg_enable_subtree_or_fail "$parent" nested_weight; then
        case_done "$dir"
        return 0
    fi
    if ! a=$(cg_group "$parent" a) || ! b=$(cg_group "$parent" b); then
        record FAIL nested_weight "trial $trial cannot create the nested groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 100 || ! cg_weight "$b" 200; then
        record FAIL nested_weight "trial $trial cannot write the nested weights"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$a" nested_a || ! start_burn "$b" nested_b; then
        record FAIL nested_weight "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL nested_weight "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health nested_weight; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" ua ub
    ratio=$(fp_ratio "$ua" "$ub")
    if num_in_range "$ratio" 1.8 2.2; then
        status=PASS
    fi
    NESTED_RATIOS+=("$ratio")
    extra=$(printf '"trial":%d,"a_usec":%s,"b_usec":%s,"ratio":%s' \
        "$trial" "$ua" "$ub" "$ratio")
    record "$status" nested_weight \
        "trial $trial nested weight 100:200 ratio $ratio, expected 1.8 to 2.2" "$extra"
}

# ---------------------------------------------------------------------
# A-04 threaded fixture.
#
# The parent is domain threaded and holds two direct normal tasks. It has
# one threaded child of weight 100 with one normal task. The three
# siblings get one third of the parent service each. cpu.stat usage is
# hierarchical, so the direct share is the parent usage minus the child
# usage.
# ---------------------------------------------------------------------

run_threaded_trial() {
    local -r trial="$1"
    local dir=""
    local parent=""
    local child=""
    local parent_type=""
    local child_type=""
    local worker=""
    local state=""
    local pair=""
    local total=0
    local child_us=0
    local direct_us=0
    local direct_ratio=""
    local child_ratio=""
    local procs_eopnotsupp=1
    local direct_count=0
    local child_count=0
    local tid=""
    local i=0
    local status=FAIL
    local extra=""

    if ! dir=$(case_root threaded_fixture threaded); then
        return 0
    fi
    if ! parent=$(cg_group "$dir" parent); then
        record FAIL threaded_fixture "trial $trial cannot create the parent"
        case_done "$dir"
        return 0
    fi
    if ! cg_enable_subtree_or_fail "$parent" threaded_fixture; then
        case_done "$dir"
        return 0
    fi
    if ! child=$(cg_threaded_group "$parent" child); then
        record FAIL threaded_fixture "trial $trial cannot create the threaded child"
        case_done "$dir"
        return 0
    fi
    parent_type=$(cg_type "$parent")
    child_type=$(cg_type "$child")
    if [[ "$parent_type" != "domain threaded" || "$child_type" != "threaded" ]]; then
        record FAIL threaded_fixture \
            "trial $trial types are '$parent_type' and '$child_type', expected 'domain threaded' and 'threaded'"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$child" 100; then
        record FAIL threaded_fixture "trial $trial cannot write the child weight"
        case_done "$dir"
        return 0
    fi
    state="$HARNESS_TMP/thread-state.$$.$trial"
    : >"$state"
    if ! start_worker "$parent" "$CPU" "$HARNESS_TMP/threaded.log" \
        "$THREADED_WORKER" "$parent" "$child" "$CPU" 3600 "$state" >/dev/null; then
        record FAIL threaded_fixture "trial $trial cannot start the threaded fixture"
        case_done "$dir"
        return 0
    fi
    worker=$HARNESS_LAST_PID
    # The three threads report their TID after they pin and, for the third
    # thread, after it moves into the threaded child.
    for (( i = 0; i < 200; i++ )); do
        if [[ "$(grep -c . "$state" 2>/dev/null || true)" -ge 3 ]]; then
            break
        fi
        sleep 0.01
    done
    while IFS= read -r tid; do
        if [[ -z "$tid" ]]; then
            continue
        fi
        if cg_has_pid "$child" cgroup.threads "$tid"; then
            child_count=$((child_count + 1))
        elif cg_has_pid "$parent" cgroup.threads "$tid"; then
            direct_count=$((direct_count + 1))
        fi
    done <"$state"
    if cat "$child/cgroup.procs" >/dev/null 2>&1; then
        procs_eopnotsupp=0
    fi
    if (( direct_count != 2 || child_count != 1 || procs_eopnotsupp != 1 )); then
        record FAIL threaded_fixture \
            "trial $trial membership direct=$direct_count child=$child_count procs_eopnotsupp=$procs_eopnotsupp, expected 2 direct, 1 child and an EOPNOTSUPP procs read"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair=$(measure_pair "$parent" "$child" "$WINDOW"); then
        record FAIL threaded_fixture "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health threaded_fixture; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" total child_us
    if (( total <= 0 || child_us < 0 )); then
        record FAIL threaded_fixture "trial $trial parent usage $total is not usable"
        return 0
    fi
    direct_us=$((total - child_us))
    direct_ratio=$(awk -v direct="$direct_us" -v total="$total" \
        'BEGIN { printf "%.4f", 1.5 * direct / total }')
    child_ratio=$(awk -v child="$child_us" -v total="$total" \
        'BEGIN { printf "%.4f", 3.0 * child / total }')
    if num_in_range "$direct_ratio" 0.8 1.25 && num_in_range "$child_ratio" 0.8 1.25; then
        status=PASS
    fi
    THREADED_RATIOS+=("$direct_ratio")
    extra=$(printf '"trial":%d,"parent_type":"%s","child_type":"%s","parent_usec":%s,"child_usec":%s,"direct_usec":%s,"direct_to_third":%s,"child_to_third":%s,"direct_tasks":%d,"child_tasks":%d,"procs_eopnotsupp":%d' \
        "$trial" "$parent_type" "$child_type" "$total" "$child_us" "$direct_us" \
        "$direct_ratio" "$child_ratio" "$direct_count" "$child_count" "$procs_eopnotsupp")
    record "$status" threaded_fixture \
        "trial $trial direct share to one third $direct_ratio child share $child_ratio, expected 0.8 to 1.25" "$extra"
}

# ---------------------------------------------------------------------
# A-05 unequal populations.
# ---------------------------------------------------------------------

run_unequal_trial() {
    local -r trial="$1"
    local dir=""
    local a=""
    local b=""
    local share=""
    local pair=""
    local ua=0
    local ub=0
    local before=""
    local after=""
    local pid=""
    local previous=0
    local current=0
    local smallest=0
    local largest=0
    local first=1
    local apids=()
    local bpids=()
    local i=0
    local status=PASS
    local extra=""

    if ! dir=$(case_root unequal_populations unequal); then
        return 0
    fi
    if ! a=$(cg_group "$dir" a) || ! b=$(cg_group "$dir" b); then
        record FAIL unequal_populations "trial $trial cannot create the groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 100 || ! cg_weight "$b" 100; then
        record FAIL unequal_populations "trial $trial cannot write cpu.weight"
        case_done "$dir"
        return 0
    fi
    for (( i = 1; i <= 4; i++ )); do
        if ! start_burn "$a" "uneq_a$i"; then
            record FAIL unequal_populations "trial $trial cannot start worker a$i"
            case_done "$dir"
            return 0
        fi
        apids+=("$HARNESS_LAST_PID")
    done
    if ! start_burn "$b" uneq_b; then
        record FAIL unequal_populations "trial $trial cannot start worker b"
        case_done "$dir"
        return 0
    fi
    bpids+=("$HARNESS_LAST_PID")
    sleep "$SETTLE"
    if ! before=$(cg_task_runtimes "${apids[@]}"); then
        record FAIL unequal_populations "trial $trial cannot read the task runtimes"
        case_done "$dir"
        return 0
    fi
    if ! pair=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL unequal_populations "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! after=$(cg_task_runtimes "${apids[@]}"); then
        record FAIL unequal_populations "trial $trial cannot read the task runtimes again"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health unequal_populations; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" ua ub
    share=$(fp_share "$ua" "$ub")
    if ! num_in_range "$share" 0.45 0.55; then
        status=FAIL
    fi
    for pid in "${apids[@]}"; do
        if ! previous=$(table_value "$before" "$pid") ||
           ! current=$(table_value "$after" "$pid"); then
            status=FAIL
            continue
        fi
        current=$((current - previous))
        if (( first )); then
            smallest=$current
            largest=$current
            first=0
        else
            if (( current < smallest )); then
                smallest=$current
            fi
            if (( current > largest )); then
                largest=$current
            fi
        fi
    done
    if (( smallest <= 0 || largest * 10 > smallest * 11 )); then
        status=FAIL
    fi
    UNEQUAL_SHARES+=("$share")
    extra=$(printf '"trial":%d,"a_usec":%s,"b_usec":%s,"a_share":%s,"tasks_a":4,"tasks_b":1,"task_min_usec":%s,"task_max_usec":%s' \
        "$trial" "$ua" "$ub" "$share" "$smallest" "$largest")
    record "$status" unequal_populations \
        "trial $trial group share $share, per-task ${smallest}us to ${largest}us, expected 0.45 to 0.55 and within 10 percent" "$extra"
}

# ---------------------------------------------------------------------
# A-06 ancestor reweight.
# ---------------------------------------------------------------------

run_ancestor_trial() {
    local -r trial="$1"
    local dir=""
    local parent=""
    local a=""
    local b=""
    local one=""
    local two=""
    local subtree_pair=""
    local split_pair=""
    local ua=0
    local ub=0
    local u1=0
    local u2=0
    local subtree=""
    local split=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root ancestor_reweight ancestor); then
        return 0
    fi
    if ! parent=$(cg_group "$dir" parent); then
        record FAIL ancestor_reweight "trial $trial cannot create the parent"
        case_done "$dir"
        return 0
    fi
    if ! cg_enable_subtree_or_fail "$parent" ancestor_reweight; then
        case_done "$dir"
        return 0
    fi
    if ! a=$(cg_group "$parent" a) || ! b=$(cg_group "$parent" b); then
        record FAIL ancestor_reweight "trial $trial cannot create the siblings"
        case_done "$dir"
        return 0
    fi
    if ! cg_enable_subtree_or_fail "$a" ancestor_reweight; then
        case_done "$dir"
        return 0
    fi
    if ! one=$(cg_group "$a" one) || ! two=$(cg_group "$a" two); then
        record FAIL ancestor_reweight "trial $trial cannot create the grandchildren"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 100 || ! cg_weight "$b" 100 ||
       ! cg_weight "$one" 100 || ! cg_weight "$two" 200; then
        record FAIL ancestor_reweight "trial $trial cannot write the weights"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$one" ancestor_one || ! start_burn "$two" ancestor_two ||
       ! start_burn "$b" ancestor_b; then
        record FAIL ancestor_reweight "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! cg_weight "$a" 200; then
        record FAIL ancestor_reweight "trial $trial cannot reweight the ancestor"
        case_done "$dir"
        return 0
    fi
    sleep 0.2
    if ! subtree_pair=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL ancestor_reweight "trial $trial cannot read the subtree usage"
        case_done "$dir"
        return 0
    fi
    if ! split_pair=$(measure_pair "$one" "$two" "$WINDOW"); then
        record FAIL ancestor_reweight "trial $trial cannot read the internal usage"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health ancestor_reweight; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$subtree_pair" ua ub
    read_pair "$split_pair" u1 u2
    subtree=$(fp_ratio "$ua" "$ub")
    split=$(fp_ratio "$u1" "$u2")
    if num_in_range "$subtree" 1.8 2.2 && num_in_range "$split" 1.8 2.2; then
        status=PASS
    fi
    ANCESTOR_RATIOS+=("$subtree")
    extra=$(printf '"trial":%d,"subtree_usec":%s,"sibling_usec":%s,"subtree_ratio":%s,"internal_ratio":%s,"one_usec":%s,"two_usec":%s' \
        "$trial" "$ua" "$ub" "$subtree" "$split" "$u1" "$u2")
    record "$status" ancestor_reweight \
        "trial $trial subtree ratio $subtree internal ratio $split, expected 1.8 to 2.2" "$extra"
}

# ---------------------------------------------------------------------
# A-07 cpu.idle group.
# ---------------------------------------------------------------------

run_idle_group_trial() {
    local -r trial="$1"
    local dir=""
    local idle=""
    local normal=""
    local pair=""
    local ui=0
    local un=0
    local share=""
    local idle_value=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root cpu_idle_group idle); then
        return 0
    fi
    if ! idle=$(cg_group "$dir" idle) || ! normal=$(cg_group "$dir" normal); then
        record FAIL cpu_idle_group "trial $trial cannot create the groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$idle" 100 || ! cg_weight "$normal" 100 ||
       ! cg_idle "$idle" 1; then
        record FAIL cpu_idle_group "trial $trial cannot write the weights or cpu.idle"
        case_done "$dir"
        return 0
    fi
    idle_value=$(cg_file "$idle" cpu.idle)
    if [[ "$idle_value" != "1" ]]; then
        record FAIL cpu_idle_group "trial $trial cpu.idle reads '${idle_value}' after writing 1"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$idle" idle_group || ! start_burn "$normal" idle_normal; then
        record FAIL cpu_idle_group "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair=$(measure_pair "$idle" "$normal" "$WINDOW"); then
        record FAIL cpu_idle_group "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health cpu_idle_group; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" ui un
    share=$(fp_share "$ui" "$un")
    if num_in_range "$share" 0.02 0.04; then
        status=PASS
    fi
    IDLE_GROUP_SHARES+=("$share")
    extra=$(printf '"trial":%d,"idle_usec":%s,"normal_usec":%s,"idle_share":%s,"within_five_percent":%s' \
        "$trial" "$ui" "$un" "$share" \
        "$(num_in_range "$share" 0 0.05 && printf true || printf false)")
    record "$status" cpu_idle_group \
        "trial $trial idle group share $share, expected 0.02 to 0.04" "$extra"
}

# ---------------------------------------------------------------------
# A-08 SCHED_IDLE task.
# ---------------------------------------------------------------------

run_sched_idle_trial() {
    local -r trial="$1"
    local dir=""
    local group=""
    local normal=""
    local idle=""
    local policy=""
    local before=""
    local after=""
    local n0=""
    local n1=""
    local i0=""
    local i1=""
    local normal_us=0
    local idle_us=0
    local share=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root sched_idle_task schedidle); then
        return 0
    fi
    if ! group=$(cg_group "$dir" group); then
        record FAIL sched_idle_task "trial $trial cannot create the group"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$group" 100; then
        record FAIL sched_idle_task "trial $trial cannot write cpu.weight"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$group" sidle_normal; then
        record FAIL sched_idle_task "trial $trial cannot start the normal worker"
        case_done "$dir"
        return 0
    fi
    normal=$HARNESS_LAST_PID
    if ! start_idle_burn "$group" sidle_idle; then
        record FAIL sched_idle_task "trial $trial cannot start the SCHED_IDLE worker"
        case_done "$dir"
        return 0
    fi
    idle=$HARNESS_LAST_PID
    if ! cg_wait_task_policy "$idle" SCHED_IDLE 2; then
        record FAIL sched_idle_task "trial $trial the worker is not SCHED_IDLE, policy is '$(cg_task_policy "$idle")'"
        case_done "$dir"
        return 0
    fi
    policy=$(cg_task_policy "$idle")
    sleep "$SETTLE"
    if ! before=$(cg_task_runtimes "$normal" "$idle"); then
        record FAIL sched_idle_task "trial $trial cannot read the task runtimes"
        case_done "$dir"
        return 0
    fi
    sleep "$WINDOW"
    if ! after=$(cg_task_runtimes "$normal" "$idle"); then
        record FAIL sched_idle_task "trial $trial cannot read the task runtimes again"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health sched_idle_task; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    if ! n0=$(table_value "$before" "$normal") ||
       ! n1=$(table_value "$after" "$normal") ||
       ! i0=$(table_value "$before" "$idle") ||
       ! i1=$(table_value "$after" "$idle"); then
        record FAIL sched_idle_task "trial $trial cannot match the task runtimes"
        return 0
    fi
    normal_us=$((n1 - n0))
    idle_us=$((i1 - i0))
    share=$(fp_share "$idle_us" "$normal_us")
    if [[ "$policy" == "SCHED_IDLE" ]] && num_in_range "$share" 0.02 0.04; then
        status=PASS
    fi
    SCHED_IDLE_SHARES+=("$share")
    extra=$(printf '"trial":%d,"policy":"%s","normal_usec":%s,"idle_usec":%s,"idle_share":%s' \
        "$trial" "$policy" "$normal_us" "$idle_us" "$share")
    record "$status" sched_idle_task \
        "trial $trial policy $policy share $share, expected SCHED_IDLE at 0.02 to 0.04" "$extra"
}

# ---------------------------------------------------------------------
# A-09 equal groups with idle off.
# ---------------------------------------------------------------------

run_idle_off_trial() {
    local -r trial="$1"
    local dir=""
    local a=""
    local b=""
    local pair=""
    local ua=0
    local ub=0
    local share=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root idle_off_equal off); then
        return 0
    fi
    if ! a=$(cg_group "$dir" a) || ! b=$(cg_group "$dir" b); then
        record FAIL idle_off_equal "trial $trial cannot create the groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 100 || ! cg_weight "$b" 100; then
        record FAIL idle_off_equal "trial $trial cannot write cpu.weight"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$a" off_a || ! start_burn "$b" off_b; then
        record FAIL idle_off_equal "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair=$(measure_pair "$a" "$b" "$WINDOW"); then
        record FAIL idle_off_equal "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health idle_off_equal; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" ua ub
    share=$(fp_share "$ua" "$ub")
    if num_in_range "$share" 0.45 0.55; then
        status=PASS
    fi
    IDLE_OFF_SHARES+=("$share")
    extra=$(printf '"trial":%d,"a_usec":%s,"b_usec":%s,"a_share":%s' \
        "$trial" "$ua" "$ub" "$share")
    record "$status" idle_off_equal \
        "trial $trial equal groups with idle off share $share, expected 0.45 to 0.55" "$extra"
}

# ---------------------------------------------------------------------
# A-10 both idle levels.
#
# An idle group holds one SCHED_IDLE task and one normal task, both
# direct. It competes with a normal weight-100 group that holds one normal
# task. The idle task divides the parent service at the group level and
# at the task level, 3/103 twice, which is 0.0848 percent.
# ---------------------------------------------------------------------

run_idle_both_trial() {
    local -r trial="$1"
    local dir=""
    local idle_group=""
    local normal_group=""
    local normal_task=""
    local idle_task=""
    local policy=""
    local total=0
    local idle_us=0
    local share=""
    local pair=""
    local ui=0
    local un=0
    local status=FAIL
    local extra=""

    if ! dir=$(case_root idle_both_levels both); then
        return 0
    fi
    if ! idle_group=$(cg_group "$dir" idle) || ! normal_group=$(cg_group "$dir" normal); then
        record FAIL idle_both_levels "trial $trial cannot create the groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$idle_group" 100 || ! cg_weight "$normal_group" 100 ||
       ! cg_idle "$idle_group" 1; then
        record FAIL idle_both_levels "trial $trial cannot write cpu.weight or cpu.idle"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$idle_group" both_normal; then
        record FAIL idle_both_levels "trial $trial cannot start the normal task"
        case_done "$dir"
        return 0
    fi
    normal_task=$HARNESS_LAST_PID
    if ! start_idle_burn "$idle_group" both_idle; then
        record FAIL idle_both_levels "trial $trial cannot start the SCHED_IDLE task"
        case_done "$dir"
        return 0
    fi
    idle_task=$HARNESS_LAST_PID
    if ! cg_wait_task_policy "$idle_task" SCHED_IDLE 2; then
        record FAIL idle_both_levels "trial $trial the worker is not SCHED_IDLE, policy is '$(cg_task_policy "$idle_task")'"
        case_done "$dir"
        return 0
    fi
    policy=$(cg_task_policy "$idle_task")
    if ! start_burn "$normal_group" both_other; then
        record FAIL idle_both_levels "trial $trial cannot start the competing normal task"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! idle_us=$(cg_task_runtime_us "$idle_task"); then
        record FAIL idle_both_levels "trial $trial cannot read the idle task runtime"
        case_done "$dir"
        return 0
    fi
    if ! pair=$(measure_pair "$idle_group" "$normal_group" "$IDLE_SEC"); then
        record FAIL idle_both_levels "trial $trial cannot read cpu.stat over $IDLE_SEC s"
        case_done "$dir"
        return 0
    fi
    if ! total=$(cg_task_runtime_us "$idle_task"); then
        record FAIL idle_both_levels "trial $trial cannot read the idle task runtime again"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health idle_both_levels; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_pair "$pair" ui un
    total=$((total - idle_us))
    if (( ui + un <= 0 )); then
        record FAIL idle_both_levels "trial $trial total service $((ui + un))us is not usable"
        return 0
    fi
    share=$(awk -v idle="$total" -v service="$((ui + un))" \
        'BEGIN { printf "%.8f", idle / service }')
    if [[ "$policy" == "SCHED_IDLE" ]] && num_in_range "$share" 0.0006 0.0011; then
        status=PASS
    fi
    IDLE_BOTH_SHARES+=("$share")
    extra=$(printf '"trial":%d,"seconds":%d,"policy":"%s","idle_usec":%s,"service_usec":%s,"idle_share":%s' \
        "$trial" "$IDLE_SEC" "$policy" "$total" "$((ui + un))" "$share")
    record "$status" idle_both_levels \
        "trial $trial idle task share $share over $IDLE_SEC s, expected 0.0006 to 0.0011" "$extra"
}

# ---------------------------------------------------------------------
# A-11 idle run after normal work stops.
#
# The idle task is starved by two normal tasks. When both stop, the idle
# task must run. The poll requires 2 ms of new runtime, which a starved
# task cannot reach inside the bound without being scheduled.
# ---------------------------------------------------------------------

run_idle_wakeup_trial() {
    local -r trial="$1"
    local dir=""
    local idle_group=""
    local normal_group=""
    local normal_a=""
    local normal_b=""
    local idle_task=""
    local policy=""
    local base=0
    local latency=0
    local start=0
    local status=FAIL
    local extra=""

    if ! dir=$(case_root idle_wakeup wake); then
        return 0
    fi
    if ! idle_group=$(cg_group "$dir" idle) || ! normal_group=$(cg_group "$dir" normal); then
        record FAIL idle_wakeup "trial $trial cannot create the groups"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$idle_group" 100 || ! cg_weight "$normal_group" 100 ||
       ! cg_idle "$idle_group" 1; then
        record FAIL idle_wakeup "trial $trial cannot write cpu.weight or cpu.idle"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$idle_group" wake_normal_a; then
        record FAIL idle_wakeup "trial $trial cannot start the first normal worker"
        case_done "$dir"
        return 0
    fi
    normal_a=$HARNESS_LAST_PID
    if ! start_burn "$normal_group" wake_normal_b; then
        record FAIL idle_wakeup "trial $trial cannot start the second normal worker"
        case_done "$dir"
        return 0
    fi
    normal_b=$HARNESS_LAST_PID
    if ! start_idle_burn "$idle_group" wake_idle; then
        record FAIL idle_wakeup "trial $trial cannot start the idle task"
        case_done "$dir"
        return 0
    fi
    idle_task=$HARNESS_LAST_PID
    if ! cg_wait_task_policy "$idle_task" SCHED_IDLE 2; then
        record FAIL idle_wakeup "trial $trial the worker is not SCHED_IDLE, policy is '$(cg_task_policy "$idle_task")'"
        case_done "$dir"
        return 0
    fi
    policy=$(cg_task_policy "$idle_task")
    sleep "$SETTLE"
    if ! base=$(cg_task_runtime_us "$idle_task"); then
        record FAIL idle_wakeup "trial $trial cannot read the idle task runtime"
        case_done "$dir"
        return 0
    fi
    # The poll owns the clock: it starts immediately after the signal, and
    # it needs 2 ms of new runtime so the tail of a starved service slot
    # cannot pass the bound.
    kill -TERM "$normal_a" "$normal_b" 2>/dev/null || true
    if ! latency=$(cg_wait_runtime_growth "$idle_task" "$base" 2000 200000); then
        record FAIL idle_wakeup "trial $trial the idle task did not run within 200 ms"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health idle_wakeup; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    if [[ "$policy" == "SCHED_IDLE" ]] && (( latency <= 10000 )); then
        status=PASS
    fi
    IDLE_LATENCIES+=("$latency")
    extra=$(printf '"trial":%d,"policy":"%s","latency_us":%s,"limit_us":10000' \
        "$trial" "$policy" "$latency")
    record "$status" idle_wakeup \
        "trial $trial idle task ran after $latency us, expected at most 10000 us" "$extra"
}

# ---------------------------------------------------------------------
# A-12 cpu.max 50000/100000.
# ---------------------------------------------------------------------

run_cpu_max_trial() {
    local -r trial="$1"
    local dir=""
    local group=""
    local a0=0
    local a1=0
    local used=0
    local rate=""
    local nr0=0
    local nr1=0
    local th0=0
    local th1=0
    local sched0=0
    local sched1=0
    local status=FAIL
    local extra=""

    if ! dir=$(case_root cpu_max max); then
        return 0
    fi
    if ! group=$(cg_group "$dir" group); then
        record FAIL cpu_max "trial $trial cannot create the group"
        case_done "$dir"
        return 0
    fi
    if ! cg_max "$group" 50000 100000 || ! cg_burst "$group" 0; then
        record FAIL cpu_max "trial $trial cannot write cpu.max"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$group" max_worker; then
        record FAIL cpu_max "trial $trial cannot start the worker"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! has_stats_line; then
        record BLOCKED cpu_max "the scheduler printed no statistics line; the throttle counter is unreadable"
        case_done "$dir"
        return 0
    fi
    if ! a0=$(cg_usage_us "$group") || ! nr0=$(cpu_stat_value "$group" nr_throttled) ||
       ! th0=$(cpu_stat_value "$group" throttled_usec); then
        record FAIL cpu_max "trial $trial cannot read the first counters"
        case_done "$dir"
        return 0
    fi
    sched0=$(sched_counter throttled)
    sleep "$WINDOW"
    if ! a1=$(cg_usage_us "$group") || ! nr1=$(cpu_stat_value "$group" nr_throttled) ||
       ! th1=$(cpu_stat_value "$group" throttled_usec); then
        record FAIL cpu_max "trial $trial cannot read the second counters"
        case_done "$dir"
        return 0
    fi
    sched1=$(sched_counter throttled)
    if ! check_scheduler_health cpu_max; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    used=$((a1 - a0))
    nr0=${nr0:-0}
    nr1=${nr1:-0}
    th0=${th0:-0}
    th1=${th1:-0}
    rate=$(fp_scale "$used" "$((WINDOW * 1000000))")
    if num_in_range "$rate" 0.45 0.55 && (( sched1 > sched0 )); then
        status=PASS
    fi
    CPU_MAX_RATES+=("$rate")
    extra=$(printf '"trial":%d,"rate":%s,"usage_usec":%s,"scheduler_throttled_before":%s,"scheduler_throttled_after":%s,"nr_throttled_before":%s,"nr_throttled_after":%s,"throttled_usec_before":%s,"throttled_usec_after":%s' \
        "$trial" "$rate" "$used" "$sched0" "$sched1" "$nr0" "$nr1" "$th0" "$th1")
    record "$status" cpu_max \
        "trial $trial rate $rate scheduler throttled $sched0 to $sched1, expected 0.45 to 0.55 and a rising scheduler counter" "$extra"
}

# ---------------------------------------------------------------------
# A-13 yield-heavy ledger.
#
# The per-task runtime from schedstat must match the group cpu.stat delta
# within 2 percent. The group stays at the quota, so a slot charge into
# cpu.max would show as a lower rate, and a double settle would show as a
# group delta above the task runtime.
# ---------------------------------------------------------------------

run_ledger_trial() {
    local -r trial="$1"
    local dir=""
    local group=""
    local worker=""
    local u0=0
    local u1=0
    local r0=0
    local r1=0
    local y0=0
    local y1=0
    local usage=0
    local task_us=0
    local deviation=""
    local rate=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root ledger_yield ledger); then
        return 0
    fi
    if ! group=$(cg_group "$dir" group); then
        record FAIL ledger_yield "trial $trial cannot create the group"
        case_done "$dir"
        return 0
    fi
    if ! cg_max "$group" 50000 100000; then
        record FAIL ledger_yield "trial $trial cannot write cpu.max"
        case_done "$dir"
        return 0
    fi
    if ! start_worker "$group" "$CPU" "$HARNESS_TMP/ledger.log" \
        "$WORKLOAD" yield 3600 >/dev/null; then
        record FAIL ledger_yield "trial $trial cannot start the yield-heavy worker"
        case_done "$dir"
        return 0
    fi
    worker=$HARNESS_LAST_PID
    sleep "$SETTLE"
    if ! u0=$(cg_usage_us "$group") || ! r0=$(cg_task_runtime_us "$worker"); then
        record FAIL ledger_yield "trial $trial cannot read the first counters"
        case_done "$dir"
        return 0
    fi
    y0=$(sched_counter yields)
    sleep "$WINDOW"
    if ! u1=$(cg_usage_us "$group") || ! r1=$(cg_task_runtime_us "$worker"); then
        record FAIL ledger_yield "trial $trial cannot read the second counters"
        case_done "$dir"
        return 0
    fi
    y1=$(sched_counter yields)
    if ! check_scheduler_health ledger_yield; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    usage=$((u1 - u0))
    task_us=$((r1 - r0))
    rate=$(fp_scale "$usage" "$((WINDOW * 1000000))")
    if (( usage > 0 )); then
        deviation=$(awk -v usage="$usage" -v task="$task_us" \
            'BEGIN { d = task - usage; if (d < 0) d = -d; printf "%.6f", d / usage }')
    else
        deviation=999
    fi
    if num_in_range "$deviation" 0 0.02 &&
       num_in_range "$rate" 0.45 0.55 && (( y1 > y0 )); then
        status=PASS
    fi
    LEDGER_DEVIATIONS+=("$deviation")
    extra=$(printf '"trial":%d,"usage_usec":%s,"task_runtime_usec":%s,"deviation":%s,"rate":%s,"scheduler_yields_before":%s,"scheduler_yields_after":%s' \
        "$trial" "$usage" "$task_us" "$deviation" "$rate" "$y0" "$y1")
    record "$status" ledger_yield \
        "trial $trial task to cpu.stat deviation $deviation rate $rate yields $y0 to $y1" "$extra"
}

# ---------------------------------------------------------------------
# A-14 nested quota: parent 60 percent, child 50 percent weight 1000.
# ---------------------------------------------------------------------

run_quota_nested_trial() {
    local -r trial="$1"
    local dir=""
    local parent=""
    local a=""
    local b=""
    local pair=""
    local up=0
    local ua=0
    local ub=0
    local rate_p=""
    local rate_a=""
    local rate_b=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root quota_nested qn); then
        return 0
    fi
    if ! parent=$(cg_group "$dir" parent); then
        record FAIL quota_nested "trial $trial cannot create the parent"
        case_done "$dir"
        return 0
    fi
    if ! cg_enable_subtree_or_fail "$parent" quota_nested; then
        case_done "$dir"
        return 0
    fi
    if ! a=$(cg_group "$parent" a) || ! b=$(cg_group "$parent" b); then
        record FAIL quota_nested "trial $trial cannot create the children"
        case_done "$dir"
        return 0
    fi
    if ! cg_max "$parent" 60000 100000 || ! cg_max "$a" 50000 100000 ||
       ! cg_max "$b" max 100000; then
        record FAIL quota_nested "trial $trial cannot write the quotas"
        case_done "$dir"
        return 0
    fi
    if ! cg_weight "$a" 1000 || ! cg_weight "$b" 100; then
        record FAIL quota_nested "trial $trial cannot write the weights"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$a" qn_a || ! start_burn "$b" qn_b; then
        record FAIL quota_nested "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! pair=$(measure_parent_children "$parent" "$a" "$b" "$WINDOW"); then
        record FAIL quota_nested "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health quota_nested; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    read_triple "$pair" up ua ub
    rate_p=$(fp_scale "$up" "$((WINDOW * 1000000))")
    rate_a=$(fp_scale "$ua" "$((WINDOW * 1000000))")
    rate_b=$(fp_scale "$ub" "$((WINDOW * 1000000))")
    if num_in_range "$rate_a" 0.44 0.51 &&
       num_in_range "$rate_p" 0.45 0.61 &&
       num_in_range "$rate_b" 0.04 0.16; then
        status=PASS
    fi
    QUOTA_NESTED_RATES+=("$rate_a")
    extra=$(printf '"trial":%d,"parent_rate":%s,"child_a_rate":%s,"child_b_rate":%s,"parent_usec":%s,"a_usec":%s,"b_usec":%s,"expected":"a<=0.51 parent<=0.61 b=remainder"' \
        "$trial" "$rate_p" "$rate_a" "$rate_b" "$up" "$ua" "$ub")
    record "$status" quota_nested \
        "trial $trial parent $rate_p child A $rate_a child B $rate_b" "$extra"
}

# Print parent, child A and child B usage deltas over one window.
measure_parent_children() {
    local -r parent="$1"
    local -r a="$2"
    local -r b="$3"
    local -r seconds="$4"
    local p0=""
    local a0=""
    local b0=""
    local p1=""
    local a1=""
    local b1=""

    p0=$(cg_usage_us "$parent") || return 1
    a0=$(cg_usage_us "$a") || return 1
    b0=$(cg_usage_us "$b") || return 1
    sleep "$seconds"
    p1=$(cg_usage_us "$parent") || return 1
    a1=$(cg_usage_us "$a") || return 1
    b1=$(cg_usage_us "$b") || return 1
    printf '%s %s %s\n' "$((p1 - p0))" "$((a1 - a0))" "$((b1 - b0))"
}

# Split "p a b" into three integers. The harness IFS keeps a space
# separated triple in one field, so the split is explicit.
read_triple() {
    local -r text="$1"
    local -n first="$2"
    local -n second="$3"
    local -n third="$4"

    IFS=' ' read -r first second third <<<"$text"
}

# ---------------------------------------------------------------------
# A-15 shared quota on two CPUs.
# ---------------------------------------------------------------------

run_quota_shared_trial() {
    local -r trial="$1"
    local dir=""
    local group=""
    local used=0
    local rate=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root quota_shared qs); then
        return 0
    fi
    if ! group=$(cg_group "$dir" group); then
        record FAIL quota_shared "trial $trial cannot create the group"
        case_done "$dir"
        return 0
    fi
    if ! cg_max "$group" 100000 100000; then
        record FAIL quota_shared "trial $trial cannot write cpu.max"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$group" qs_a || ! start_burn_on "$group" "$CPU2" qs_b; then
        record FAIL quota_shared "trial $trial cannot start the workers"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! used=$(measure_group "$group" "$WINDOW"); then
        record FAIL quota_shared "trial $trial cannot read cpu.stat"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health quota_shared; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    rate=$(fp_scale "$used" "$((WINDOW * 1000000))")
    if num_in_range "$rate" 0.9 1.1; then
        status=PASS
    fi
    QUOTA_SHARED_RATES+=("$rate")
    extra=$(printf '"trial":%d,"cpus":"%s,%s","usage_usec":%s,"rate_of_one_cpu":%s' \
        "$trial" "$CPU" "$CPU2" "$used" "$rate")
    record "$status" quota_shared \
        "trial $trial shared 100 percent quota used $rate of one CPU, expected 0.9 to 1.1" "$extra"
}

# ---------------------------------------------------------------------
# A-16 live quota update.
# ---------------------------------------------------------------------

run_quota_live_trial() {
    local -r trial="$1"
    local dir=""
    local group=""
    local before_used=0
    local before_rate=""
    local after_used=0
    local after_rate=""
    local status=FAIL
    local extra=""

    if ! dir=$(case_root quota_live ql); then
        return 0
    fi
    if ! group=$(cg_group "$dir" group); then
        record FAIL quota_live "trial $trial cannot create the group"
        case_done "$dir"
        return 0
    fi
    if ! cg_max "$group" 50000 100000; then
        record FAIL quota_live "trial $trial cannot write the first quota"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$group" ql_worker; then
        record FAIL quota_live "trial $trial cannot start the worker"
        case_done "$dir"
        return 0
    fi
    sleep "$SETTLE"
    if ! before_used=$(measure_group "$group" "$WINDOW"); then
        record FAIL quota_live "trial $trial cannot read the first window"
        case_done "$dir"
        return 0
    fi
    before_rate=$(fp_scale "$before_used" "$((WINDOW * 1000000))")
    if ! cg_max "$group" 25000 100000; then
        record FAIL quota_live "trial $trial cannot change the live quota"
        case_done "$dir"
        return 0
    fi
    # One 100 ms period plus one 1 ms tick.
    sleep 0.101
    if ! after_used=$(measure_group "$group" 1); then
        record FAIL quota_live "trial $trial cannot read the settled window"
        case_done "$dir"
        return 0
    fi
    if ! check_scheduler_health quota_live; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    after_rate=$(fp_scale "$after_used" 1000000)
    if num_in_range "$before_rate" 0.45 0.55 && num_in_range "$after_rate" 0.22 0.28; then
        status=PASS
    fi
    QUOTA_LIVE_RATES+=("$after_rate")
    extra=$(printf '"trial":%d,"before_rate":%s,"after_rate":%s,"settle_ms":101,"after_usage_usec":%s' \
        "$trial" "$before_rate" "$after_rate" "$after_used")
    record "$status" quota_live \
        "trial $trial rate $before_rate then $after_rate after the live change, expected 0.45 to 0.55 then 0.22 to 0.28" "$extra"
}

# ---------------------------------------------------------------------
# A-17 move conservation.
#
# Two groups are saturated on two CPUs. A third task alternates between
# the groups and the CPUs. The old-path and the new-path cpu.stat deltas
# must sum to the runtime that the three tasks report, within one
# accounting tick. A double charge or a lost ledger shows as a gap.
# ---------------------------------------------------------------------

run_move_trial() {
    local -r trial="$1"
    local dir=""
    local a=""
    local b=""
    local burner_a=""
    local burner_b=""
    local mover=""
    local before=""
    local after=""
    local a0=0
    local b0=0
    local t1a=0
    local t2a=0
    local t3a=0
    local a1=0
    local b1=0
    local t1b=0
    local t2b=0
    local t3b=0
    local group_us=0
    local task_us=0
    local error=0
    local limit_us=0
    local snapshot_us=0
    local snap_start=0
    local snap_end=0
    local step=0
    local status=FAIL
    local extra=""

    if ! dir=$(case_root move_conservation move); then
        return 0
    fi
    if ! a=$(cg_group "$dir" a) || ! b=$(cg_group "$dir" b); then
        record FAIL move_conservation "trial $trial cannot create the groups"
        case_done "$dir"
        return 0
    fi
    if ! start_burn "$a" move_a; then
        record FAIL move_conservation "trial $trial cannot start the first burner"
        case_done "$dir"
        return 0
    fi
    burner_a=$HARNESS_LAST_PID
    if ! start_burn_on "$b" "$CPU2" move_b; then
        record FAIL move_conservation "trial $trial cannot start the second burner"
        case_done "$dir"
        return 0
    fi
    burner_b=$HARNESS_LAST_PID
    if ! start_burn "$a" move_mover; then
        record FAIL move_conservation "trial $trial cannot start the moving task"
        case_done "$dir"
        return 0
    fi
    mover=$HARNESS_LAST_PID
    sleep "$SETTLE"

    snap_start=${EPOCHREALTIME//[!0-9]/}
    snap_start=$((10#$snap_start))
    if ! before=$(cg_ledger_snapshot "$a" "$b" "$burner_a" "$burner_b" "$mover"); then
        record FAIL move_conservation "trial $trial cannot read the first counters"
        case_done "$dir"
        return 0
    fi
    snap_end=${EPOCHREALTIME//[!0-9]/}
    snapshot_us=$((10#$snap_end - snap_start))
    for (( step = 0; step < 8; step++ )); do
        if ! cg_put_task "$b" cgroup.procs "$mover"; then
            record FAIL move_conservation "trial $trial cannot move the task to group b"
            case_done "$dir"
            return 0
        fi
        taskset -pc "$CPU2" "$mover" >/dev/null 2>&1 || true
        sleep 0.3
        if ! cg_put_task "$a" cgroup.procs "$mover"; then
            record FAIL move_conservation "trial $trial cannot move the task to group a"
            case_done "$dir"
            return 0
        fi
        taskset -pc "$CPU" "$mover" >/dev/null 2>&1 || true
        sleep 0.3
    done
    snap_start=${EPOCHREALTIME//[!0-9]/}
    snap_start=$((10#$snap_start))
    if ! after=$(cg_ledger_snapshot "$a" "$b" "$burner_a" "$burner_b" "$mover"); then
        record FAIL move_conservation "trial $trial cannot read the second counters"
        case_done "$dir"
        return 0
    fi
    snap_end=${EPOCHREALTIME//[!0-9]/}
    if (( 10#$snap_end - snap_start > snapshot_us )); then
        snapshot_us=$((10#$snap_end - snap_start))
    fi
    if ! check_scheduler_health move_conservation; then
        case_done "$dir"
        return 0
    fi
    if ! kill -0 "$mover" 2>/dev/null; then
        record FAIL move_conservation "trial $trial the moving task is gone"
        case_done "$dir"
        return 0
    fi
    case_done "$dir"

    IFS=' ' read -r a0 b0 t1a t2a t3a <<<"$before"
    IFS=' ' read -r a1 b1 t1b t2b t3b <<<"$after"
    # The two ledgers are read one after the other. A task that runs
    # between the group read and its own read moves at most the snapshot
    # width, so one tick is added to the measured snapshot width. The
    # residual is what the scheduler itself lost or charged twice.
    limit_us=$((INF_ACCOUNT_TICK_US + snapshot_us))
    group_us=$(( (a1 - a0) + (b1 - b0) ))
    task_us=$(( (t1b - t1a) + (t2b - t2a) + (t3b - t3a) ))
    error=$((group_us - task_us))
    if (( error < 0 )); then
        error=$((-error))
    fi
    if (( task_us > 0 )) && (( error <= limit_us )); then
        status=PASS
    fi
    MOVE_ERRORS+=("$error")
    extra=$(printf '"trial":%d,"group_usec":%s,"task_usec":%s,"error_usec":%s,"tick_usec":%s,"snapshot_usec":%s,"limit_usec":%s' \
        "$trial" "$group_us" "$task_us" "$error" "$INF_ACCOUNT_TICK_US" "$snapshot_us" "$limit_us")
    record "$status" move_conservation \
        "trial $trial group ledger ${group_us}us task ledger ${task_us}us error ${error}us, limit ${limit_us}us (one ${INF_ACCOUNT_TICK_US}us tick plus a ${snapshot_us}us snapshot)" "$extra"
}

# ---------------------------------------------------------------------
# A-18 burst.
# ---------------------------------------------------------------------

run_burst_trial() {
    local -r trial="$1"
    local dir=""
    local group=""
    local burst_used=0
    local burst=""
    local control_used=0
    local control=""
    local steady_used=0
    local steady=""
    local gap=""
    local nr0=0
    local nr1=0
    local status=FAIL
    local extra=""

    if ! dir=$(case_root cpu_max_burst burst); then
        return 0
    fi
    if ! group=$(cg_group "$dir" group); then
        record FAIL cpu_max_burst "trial $trial cannot create the group"
        case_done "$dir"
        return 0
    fi
    if ! cg_max "$group" 50000 100000 || ! cg_burst "$group" 50000; then
        record FAIL cpu_max_burst "trial $trial cannot write cpu.max and cpu.max.burst"
        case_done "$dir"
        return 0
    fi
    # Credit preparation: 500 ms below quota with only a sleeper.
    if ! start_sleeper "$group" burst_sleeper; then
        record FAIL cpu_max_burst "trial $trial cannot start the credit sleeper"
        case_done "$dir"
        return 0
    fi
    sleep 0.5
    if ! start_burn "$group" burst_worker; then
        record FAIL cpu_max_burst "trial $trial cannot start the burst worker"
        case_done "$dir"
        return 0
    fi
    burst_used=$(measure_group "$group" 0.3) || {
        record FAIL cpu_max_burst "trial $trial cannot read the burst sample"
        case_done "$dir"
        return 0
    }
    burst=$(fp_scale "$burst_used" 300000)
    nr0=$(cpu_stat_value "$group" nr_throttled)
    # Drain for 5 s, then measure a 10 s steady window.
    sleep 5
    if ! steady_used=$(measure_group "$group" 10); then
        record FAIL cpu_max_burst "trial $trial cannot read the steady window"
        case_done "$dir"
        return 0
    fi
    steady=$(fp_scale "$steady_used" 10000000)
    nr1=$(cpu_stat_value "$group" nr_throttled)
    stop_all_workers

    # Matched zero-burst control, with the same credit preparation time.
    if ! cg_burst "$group" 0 || ! start_sleeper "$group" burst_control_sleeper; then
        record FAIL cpu_max_burst "trial $trial cannot set up the zero-burst control"
        case_done "$dir"
        return 0
    fi
    sleep 0.5
    if ! start_burn "$group" burst_control_worker; then
        record FAIL cpu_max_burst "trial $trial cannot start the control worker"
        case_done "$dir"
        return 0
    fi
    control_used=$(measure_group "$group" 0.3) || {
        record FAIL cpu_max_burst "trial $trial cannot read the control sample"
        case_done "$dir"
        return 0
    }
    control=$(fp_scale "$control_used" 300000)
    if ! check_scheduler_health cpu_max_burst; then
        case_done "$dir"
        return 0
    fi
    case_done "$dir"
    nr0=${nr0:-0}
    nr1=${nr1:-0}
    gap=$(awk -v burst="$burst" -v control="$control" 'BEGIN { printf "%.4f", burst - control }')
    if num_in_range "$burst" 0.52 1.0 &&
       num_in_range "$control" 0.45 0.55 &&
       num_in_range "$gap" 0.05 1.0 &&
       num_in_range "$steady" 0.45 0.55 &&
       (( nr1 > nr0 )); then
        status=PASS
    fi
    BURST_RATIOS+=("$burst")
    BURST_CONTROLS+=("$control")
    BURST_GAPS+=("$gap")
    extra=$(printf '"trial":%d,"burst_ratio":%s,"control_ratio":%s,"gap":%s,"steady_ratio":%s,"nr_throttled_before":%s,"nr_throttled_after":%s' \
        "$trial" "$burst" "$control" "$gap" "$steady" "$nr0" "$nr1")
    record "$status" cpu_max_burst \
        "trial $trial burst $burst control $control gap $gap steady $steady, expected burst above 0.52, gap at least 0.05 and steady 0.45 to 0.55" "$extra"
}

# ---------------------------------------------------------------------
# Teardown.
# ---------------------------------------------------------------------

teardown() {
    local faults=""
    local lost=0
    local stale=0
    local leftover=0

    stop_all_workers
    local files=""
    files=$(find "$CGROUP_PARENT" -name cgroup.procs -type f 2>/dev/null || true)
    while IFS= read -r file; do
        if [[ -n "$file" && -s "$file" ]]; then
            leftover=$((leftover + 1))
        fi
    done <<<"$files"
    if (( leftover == 0 )); then
        record PASS cgroup_empty "no task is left in a case cgroup"
    else
        record FAIL cgroup_empty "$leftover cgroup membership file(s) still list a task"
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
    rmdir -- "$CGROUP_PARENT" 2>/dev/null || true
    if [[ ! -e "$CGROUP_PARENT" ]]; then
        record PASS cgroup_cleanup "the harness cgroup removed"
    else
        record FAIL cgroup_cleanup "the harness cgroup remains at $CGROUP_PARENT"
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
        run_nested_trial "$trial"
        run_threaded_trial "$trial"
        run_unequal_trial "$trial"
        run_ancestor_trial "$trial"
        run_idle_group_trial "$trial"
        run_sched_idle_trial "$trial"
        run_idle_off_trial "$trial"
        run_idle_both_trial "$trial"
        run_idle_wakeup_trial "$trial"
        run_cpu_max_trial "$trial"
        run_ledger_trial "$trial"
        run_quota_nested_trial "$trial"
        run_quota_shared_trial "$trial"
        run_quota_live_trial "$trial"
        run_move_trial "$trial"
        run_burst_trial "$trial"
        if ! scheduler_alive; then
            record FAIL scheduler "the scheduler exited; the remaining trials are skipped"
            break
        fi
    done

    note_summary weight_ratio_median "${WEIGHT_RATIOS[@]}"
    note_summary live_ratio_median "${LIVE_RATIOS[@]}"
    note_summary nested_ratio_median "${NESTED_RATIOS[@]}"
    note_summary threaded_ratio_median "${THREADED_RATIOS[@]}"
    note_summary unequal_share_median "${UNEQUAL_SHARES[@]}"
    note_summary ancestor_ratio_median "${ANCESTOR_RATIOS[@]}"
    note_summary idle_group_share_median "${IDLE_GROUP_SHARES[@]}"
    note_summary sched_idle_share_median "${SCHED_IDLE_SHARES[@]}"
    note_summary idle_off_share_median "${IDLE_OFF_SHARES[@]}"
    note_summary idle_both_share_median "${IDLE_BOTH_SHARES[@]}"
    note_summary idle_latency_median "${IDLE_LATENCIES[@]}"
    note_summary cpu_max_rate_median "${CPU_MAX_RATES[@]}"
    note_summary ledger_deviation_median "${LEDGER_DEVIATIONS[@]}"
    note_summary quota_nested_rate_median "${QUOTA_NESTED_RATES[@]}"
    note_summary quota_shared_rate_median "${QUOTA_SHARED_RATES[@]}"
    note_summary quota_live_rate_median "${QUOTA_LIVE_RATES[@]}"
    note_summary move_error_median "${MOVE_ERRORS[@]}"
    note_summary burst_ratio_median "${BURST_RATIOS[@]}"
    note_summary burst_control_median "${BURST_CONTROLS[@]}"
    note_summary burst_gap_median "${BURST_GAPS[@]}"

    teardown
}

main "$@"
