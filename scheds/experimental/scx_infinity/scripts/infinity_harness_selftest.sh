#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_harness_selftest.sh - unit tests for the harness helpers.
#
# The tests need no root and no scheduler. They cover the pure helpers and
# the fail-closed behaviour of the harness entry points on a host.
#
# Usage:
#   scheds/experimental/scx_infinity/scripts/infinity_harness_selftest.sh
#
# Output: TAP-like PASS/FAIL lines. Exit 0 when every test passes.

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=infinity_harness_lib.sh
. "$SCRIPT_DIR/infinity_harness_lib.sh"

TOTAL=0
FAILED=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scx-infinity-selftest.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

ok() {
    TOTAL=$((TOTAL + 1))
    printf 'ok %d - %s\n' "$TOTAL" "$1"
}

not_ok() {
    TOTAL=$((TOTAL + 1))
    FAILED=$((FAILED + 1))
    printf 'not ok %d - %s\n' "$TOTAL" "$1"
    if (($# > 1)); then
        printf '# %s\n' "$2"
    fi
}

is_equal() {
    local -r name="$1"
    local -r expected="$2"
    local -r actual="$3"

    if [[ "$expected" == "$actual" ]]; then
        ok "$name"
    else
        not_ok "$name" "expected '$expected', got '$actual'"
    fi
}

is_true() {
    local -r name="$1"

    shift
    if "$@"; then
        ok "$name"
    else
        not_ok "$name"
    fi
}

is_false() {
    local -r name="$1"

    shift
    if "$@"; then
        not_ok "$name"
    else
        ok "$name"
    fi
}

# json_escape ---------------------------------------------------------
is_equal "json_escape keeps plain text" "plain" "$(json_escape plain)"
is_equal "json_escape escapes a quote" 'a\"b' "$(json_escape 'a"b')"
is_equal "json_escape escapes a backslash" 'a\\b' "$(json_escape 'a\b')"
is_equal "json_escape escapes a newline" 'a\nb' "$(json_escape $'a\nb')"

HARNESS_NAME=selftest
HARNESS_JSON_OUT=""
line=$(json_emit check PASS 'a "quoted" check' 'detail')
if command -v jq >/dev/null 2>&1; then
    if printf '%s\n' "$line" | jq -e '.status == "PASS"' >/dev/null 2>&1; then
        ok "json_emit produces valid JSON"
    else
        not_ok "json_emit produces valid JSON" "$line"
    fi
else
    ok "json_emit skips the jq check, jq is absent"
fi

# cpulist helpers -----------------------------------------------------
is_equal "cpulist_count counts a range" "16" "$(cpulist_count 0-15)"
is_equal "cpulist_count counts a mixed list" "5" "$(cpulist_count 0-2,8,10)"
is_equal "cpulist_first returns a range start" "0" "$(cpulist_first 0-3,8)"
is_equal "cpulist_first returns a single CPU" "8" "$(cpulist_first 8)"
is_equal "cpulist_expand expands a mixed list" "0 1 2 3 8" \
    "$(cpulist_expand 0-3,8 | tr '\n' ' ' | sed 's/ $//')"
is_true "cpu_in_list accepts a range member" cpu_in_list 3 0-3
is_false "cpu_in_list rejects an outside CPU" cpu_in_list 4 0-3
is_true "cpu_in_list accepts a list member" cpu_in_list 10 0-2,8,10
is_false "cpu_in_list rejects a missing CPU" cpu_in_list 9 0-2,8,10

# numeric helpers -----------------------------------------------------
is_true "num_in_range accepts the low bound" num_in_range 1.8 1.8 2.2
is_false "num_in_range rejects below the low bound" num_in_range 1.79 1.8 2.2
is_equal "fp_ratio divides" "2.0000" "$(fp_ratio 100 200)"
is_equal "fp_ratio handles a zero divisor" "999" "$(fp_ratio 0 200)"
is_equal "fp_scale divides" "0.5000" "$(fp_scale 50000 100000)"
is_equal "median_of an odd count" "2.0000" "$(median_of 1 2 3)"
is_equal "median_of an even count" "2.5000" "$(median_of 1 2 3 4)"

# read_pair ------------------------------------------------------------
# The harness IFS is newline and tab, so a plain read would keep both
# numbers of the measured pair in its first variable.
pair_a=""
pair_b=""
read_pair "2461745 2458399" pair_a pair_b
is_equal "read_pair splits the first value" "2461745" "$pair_a"
is_equal "read_pair splits the second value" "2458399" "$pair_b"

# stat_value ----------------------------------------------------------
cat >"$WORK/scheduler.log" <<'EOF'
2026-10-20 10:00:00 INFO inserts: head=100 tail=20 exempt=3 expiries=5 preemptions=2 yields=1 depth=0 cgrp: throttled=0 reenqueued=0 eff_weight=0 eff_min=0 eff_max=0 eff_samples=0 scale_q10=0 refolds=0 deq: sleep=0 sched_change=0 core_exec=0 keep=0 qui: sleep=0 sched_change=0 keep=0 cpu_moves=0 weight: joins=0 leaves=0 reweights=0 moves=0 refolds=0 underflow=0 nr_underflow=0 epoch=0 init_idle=0 idle_on=0 idle_off=0 queue: steals=4 llc=3 node=1 yield_to=2 reweight=5 stale=0 lost=0 requeues=0 weight_changes=6 queued=1 queued_cpu=0
EOF
is_equal "stat_value reads head" "100" "$(stat_value "$WORK/scheduler.log" head)"
is_equal "stat_value reads yield_to" "2" "$(stat_value "$WORK/scheduler.log" yield_to)"
is_equal "stat_value reads reweight without matching reweights" "5" "$(stat_value "$WORK/scheduler.log" reweight)"
is_equal "stat_value returns 0 for a missing key" "0" "$(stat_value "$WORK/scheduler.log" absent)"
is_equal "stat_value returns 0 for a missing log" "0" "$(stat_value "$WORK/missing.log" head)"

# worker registration ------------------------------------------------
mkdir "$WORK/fakecg"
: >"$WORK/fakecg/cgroup.procs"
if start_worker "$WORK/fakecg" 0 "$WORK/sleep.log" sleep 30 >/dev/null; then
    pid=$HARNESS_LAST_PID
    if ((${#HARNESS_WORKER_PIDS[@]} == 1)) &&
       [[ "${HARNESS_WORKER_PIDS[0]}" == "$pid" ]]; then
        ok "start_worker registers the PID in the parent shell"
    else
        not_ok "start_worker registers the PID in the parent shell"
    fi
    stop_all_workers
    if ! kill -0 "$pid" 2>/dev/null && ((${#HARNESS_WORKER_PIDS[@]} == 0)); then
        ok "stop_all_workers removes a registered worker"
    else
        not_ok "stop_all_workers removes a registered worker"
    fi
else
    not_ok "start_worker starts a test worker" "taskset or sleep failed"
fi

# fail-closed entry points --------------------------------------------
for script in infinity_feature_preflight.sh infinity_cgroup_harness.sh \
    infinity_queue_stress.sh infinity_numa_placement.sh; do
    if "$SCRIPT_DIR/$script" --help >/dev/null 2>&1; then
        ok "$script --help succeeds"
    else
        not_ok "$script --help succeeds"
    fi
    if "$SCRIPT_DIR/$script" --definitely-not-an-argument >/dev/null 2>&1; then
        not_ok "$script rejects an unknown argument"
    else
        ok "$script rejects an unknown argument"
    fi
done

# On a host without SCX_INFINITY_VM the cgroup harness must print a
# BLOCKED summary and exit 2. It must not start a scheduler or a worker.
set +e
"$SCRIPT_DIR/infinity_cgroup_harness.sh" --check >"$WORK/check.out" 2>"$WORK/check.err"
rc=$?
set -e
if (( rc == 2 )); then
    ok "the cgroup harness fails closed with exit 2"
else
    not_ok "the cgroup harness fails closed with exit 2" "exit $rc"
fi
if tail -n 1 "$WORK/check.out" | grep -q '"event":"summary".*"status":"BLOCKED"'; then
    ok "the cgroup harness prints a BLOCKED summary"
else
    not_ok "the cgroup harness prints a BLOCKED summary" "$(tail -n 1 "$WORK/check.out" 2>/dev/null || true)"
fi
if grep -q '"status":"BLOCKED","check":"vm"' "$WORK/check.out"; then
    ok "the cgroup harness blocks without a disposable VM"
else
    not_ok "the cgroup harness blocks without a disposable VM"
fi

printf '\n%d tests, %d failed\n' "$TOTAL" "$FAILED"
if (( FAILED != 0 )); then
    exit 1
fi
