# scx_infinity

Experimental sched_ext scheduler for the Infinity fair policy.

**Status: experimental. Not ready for general use.**

The tree implements revision 4.1 of `.agent/tasks/spec/spec.md`. The
policy carrier is one hierarchical entity tree per CPU, per-level
normalized service and one service slot per measured kernel tick. Spec
section 2.11 records every limit that the BPF verifier and the shared
code forced. The "Limits" section below repeats those numbers, and a
reader must not read a larger capability into this binary.

## Scope

The scheduler replaces the fair class for `SCHED_NORMAL`, `SCHED_BATCH`,
`SCHED_IDLE` and `SCHED_EXT` tasks. It enforces `cpu.weight`, `cpu.idle`
and `cpu.max` (quota, period and burst) from cgroup v2. Placement is
locality-first across the previous CPU, the local LLC, the local NUMA
node and a capacity-ranked remote CPU.

Out of scope:

- Native RT, deadline and stop scheduling. The kernel keeps those
  classes above sched_ext, and this scheduler never sees those tasks.
- DRM GPU scheduling. GPU work and the driver runqueues stay outside
  this scheduler.
- A virtual runtime tree, EEVDF lag or deadlines.
- Sub-schedulers, the cid form and `scx_prio`.
- Live CPU hotplug. A CPU set change needs a scheduler restart.

## Policy

`scx_infinity` is a root scheduler. The scheduler is split into a BPF
program in `src/bpf/main.bpf.c` and a Rust loader in `src/main.rs`.

### Entity tree

The scheduler owns one entity tree per CPU. Each cgroup level is a node
in that tree. The direct tasks of a cgroup and its child cgroups are
weighted siblings in one queue. A task and a child group compete at
their own level. There is no folded effective weight and no aggregate
task lane.

Each parent queue is a `scx_edq` from `scheds/include/lib/edq.h`,
ordered by normalized service. A running task removes its whole path
from the tree and re-enters that path at the end of each service slot. A
sched_ext local DSQ runs only the task the scheduler selected, so tree
membership, holds, removal and ordering stay under scheduler control.

A normal task entity uses `p->scx.weight`. A `SCHED_IDLE` task uses
weight 3. A group entity uses `cpu.weight`, or weight 3 when the group
has `cpu.idle=1`. The service charge advances the task entity and every
ancestor entity, each at its own weight.

### Order and selection

- Eight normal insertions pass a fixed 7:1 gate. Seven take the head and
  one takes the tail, so at most seven normal arrivals move ahead of a
  queued entity between two tail insertions.
- `SCX_ENQ_HEAD` is the only head-exempt hint. A wakeup passes the same
  gate as any other enqueue. Slice expiry, explicit yield and a partial
  preemption enter at the tail. A post-slot requeue takes the normal
  gate at every level.
- Selection reads the least-service sibling and takes the eligible band
  of one slot. It prefers the newest head over the oldest tail at the
  lower service. A head more than one slot ahead is not eligible.
- A descent removes the selected path and inserts the task into the local
  DSQ. A refused insert puts the path back instead of dropping the task.

### Cgroup controls

`cpu.max` quota, period and burst come from the existing bandwidth
library (`lib/cgroup_bw.bpf.c`). A task in a throttled group is parked on
the library's arena backlog and re-enqueued through the same gate when
the group gets time again. Actual runtime is the only input to `cpu.max`.
The policy service ledger is separate, so an explicit yield pays for its
reserved slot in the tree while `cpu.max` sees only real runtime.

`--no-cpu-max` disables the bandwidth library. A kernel without
`ops.cgroup_set_bandwidth()` clears the same path at load.

## Service slot

One `ops.tick` call is one service slot. The scheduler does not take the
slot from the configuration. It counts kernel ticks, so the slot is one
measured kernel tick and there is no quantum to set.

The measurement, one busy task pinned to CPU 0 for 5 s on the
`CONFIG_HZ=1000` guest:

```
task_tick_scx n=5001 span_ms=5001.048
 gap_ms min=0.1760 median=1.0000 p99=1.0250 max=2.8260
 gaps_gt_1.5ms=3 gaps_gt_2ms=1
```

The run had function tracing active, which adds overhead. The nominal
1 ms is the dispatch slice and the band width, not a wall-clock
promise. A late tick makes the slot longer, and a slice expiry before
the tick ends it early. `ops.tick` runs only when a task of the
scheduler's class is the donor of that runqueue, so an idle CPU does not
deliver it. A `NOHZ_FULL` tick can arrive on another CPU, and that tick
charges one nominal slot instead of a cross-CPU clock difference.

## Limits

The verifier budget and the shared code set these limits. Spec section
2.11 gives the reason, the effect and the acceptance criterion of each
one.

| Object | Limit |
| --- | --- |
| cgroup levels per task | 4, not 32 |
| group entities | 128 per CPU |
| group index | 256 slots per CPU |
| task entities | 65536 |
| band scan | 16 children per queue |
| steal | 2 peers per LLC or NUMA tier |
| preemption check | the queue head at each level |
| `cpu.max` | 2048 cgroups and 32 nesting levels |

A task in a cgroup deeper than four levels joins the deepest ancestor
that has an entity on that CPU. That ancestor carries its service. When
the 128 group entities of a CPU are in use, a new group joins the
nearest ancestor. The scheduler counts `entity_overflow`, and the task
stays runnable. At 65536 task entities, `ops.init_task()` returns
`-ENOMEM` and a fork fails. A queue whose service band holds more than
16 siblings falls back to its head for that selection and counts
`band_full`.

The arena holds pages on demand. A page request inside the shared
allocator can fail under fork churn, and the scheduler cannot see that
request. The failure path calls `scx_bpf_error()` and the scheduler
aborts. No measured run on the final build reproduced it, and the
failure is still possible.

A successful `scx_bpf_dsq_insert()` reports that the core accepted the
request. The core performs the enqueue later, on its own runqueue path.
It can drop the request if the task or the runqueue changes in the
window. A dropped request leaves the task in core custody with no
scheduler reference. The scheduler cannot close that window. It counts
a refused insert, puts the path back and names the custody state in its
diagnostic snapshots.

## Placement

Placement is locality-first. The order is:

1. The previous CPU when it is idle and allowed.
2. A fully idle physical core in the local LLC.
3. A fully idle physical core in the local NUMA node.
4. A fully idle physical core in another NUMA node, nearest first.
5. An idle SMT thread in the local LLC, the local node, then any node.
6. Capacity and queue-depth ranking when no CPU is idle.

Affinity and cpuset masks limit every step, and an offline CPU is never
selected. The waker CPU defines the local domain when it is allowed,
otherwise the previous CPU does.

At dispatch, a CPU whose tree holds no dispatchable task steals the head
of a same-LLC peer tree, then a same-NUMA peer tree. Each tier probes at
most two eligible peers from a rotating per-CPU cursor, so a peer outside
the window is reached on a later dispatch. A peer task that cannot run on
the stealing CPU is skipped. No steal crosses a NUMA node.

The loader reads `scx_utils::Topology` and fills a scheduler-local BPF
map with the node, LLC, core, SMT sibling, primary-thread and capacity
data. The placement policy stays in this scheduler. The shared utilities
carry none of it.

## Build

```
cargo build -p scx_infinity
```

The BPF object needs clang 22 or newer and a kernel built with
`CONFIG_SCHED_CLASS_EXT`. The scheduler uses the BPF arena and the
shared cgroup libraries. The VM preflight checks both:

```
sudo ./scripts/infinity_vm_preflight.sh
```

EDQ is the only queue backend. The tree has no queue build feature and
no second queue source.

For a release binary:

```
cargo build --release -p scx_infinity
```

The compatibility harness runs with:

```
make -C lib/selftests/compat test
```

## Run

```
sudo ./target/release/scx_infinity
```

`scx_infinity --help` lists the options. Press Ctrl-C to unregister the
scheduler. While it runs, `/sys/kernel/sched_ext/state` reads `enabled`.
After a clean exit it reads `disabled`. A non-root run fails at load.

## Command line

```
scx_infinity [--config PATH] [--exit-dump-len N]
             [--placement MODE] [--no-smt] [--spill-threshold N]
             [--preempt-margin-us N] [--no-cpu-max] [--verbose] [--version]
             [--trace] [--test-dsq-refuse N]
```

- `--config PATH`: read this TOML file instead of the default XDG path.
- `--exit-dump-len N`: exit debug dump buffer length, 0 selects the
  default.
- `--placement MODE`: `auto` (default) walks the full order. `llc`
  stops at the local LLC, `numa` stops at the local NUMA node, and
  `machine` skips locality and ranks every allowed CPU by capacity and
  depth. Overrides the file.
- `--no-smt`: never place new work on an SMT sibling of a busy core
  while a primary thread is available. Overrides the file.
- `--spill-threshold N`: queue depth at which a CPU is considered
  crowded, 1 to 64, default 4. The capacity fallback prefers a CPU below
  the threshold. Overrides the file.
- `--preempt-margin-us N`: minimum remaining victim slice for a wakeup
  preemption, 0 to 1000. Default 100. Overrides the file.
- `--no-cpu-max`: do not enforce `cpu.max`. `cpu.weight` and `cpu.idle`
  stay active. A kernel without `ops.cgroup_set_bandwidth()` disables the
  same path automatically.
- `--verbose`: enable libbpf and loader diagnostics.
- `--version`: print the scheduler version and exit.
- `--trace`: diagnostic only. Record the anomalous queue transitions and
  the last eight transitions of every task. Print the trace ring, the
  per-CPU snapshot and the task snapshot when the scheduler exits. The
  trace is off by default.
- `--test-dsq-refuse N`: diagnostic only, hidden. Refuse the first N
  local DSQ inserts without calling the kernel, so the requeue fallback
  runs deterministically. Requires `--trace` for the transition records.

`--quantum-us` was removed in revision 4. The option is hidden, and a
run that still passes it stops with a message that names the revision-4
change. The service slot is one measured kernel tick, so there is no
quantum to set.

Run it as root. Press Ctrl-C to unregister the scheduler.

## Configuration

The loader reads:

```
$XDG_CONFIG_HOME/scx_infinity/config.toml
```

If `XDG_CONFIG_HOME` is unset, empty or not absolute, the path is:

```
$HOME/.config/scx_infinity/config.toml
```

`--config PATH` overrides the path. A missing file is not an error: it
means the built-in defaults apply. A command-line value wins over the
file. Unknown keys and out-of-range values reject the entire file.

```toml
# scx_infinity configuration
placement = "auto"          # "auto" | "llc" | "numa" | "machine"
smt = true                  # false: physical cores only
preempt_margin_ns = 100000  # 0 ..= 1_000_000
spill_threshold = 4         # 1 ..= 64
stats_interval_ms = 1000    # 0 disables the stats line
```

The file is checked as a whole before any value is applied. All errors
are reported in one message, and a rejected file changes nothing.

There is no quantum key. A revision-3 file that still sets `quantum_ns`
is rejected as a whole, with the key name, the revision-4 reason and the
allowed keys in the error. The key is never accepted and ignored.

## Reload

Send `SIGHUP` to reread the same path:

```
kill -HUP $(pidof scx_infinity)
```

The loader parses and checks the new file, applies the command-line
overrides again, and publishes the result with one BPF map update. An
override therefore persists across a reload. If parsing or the check
fails, the error is logged, the active settings stay live, and the
scheduler keeps running. The queue order and expiry mechanics never
change on reload.

## Statistics

The loader prints one line per second. The fields, abbreviated:

```
inserts: head=... tail=... exempt=... expiries=... preemptions=... yields=... depth=...
cgrp: throttled=... reenqueued=... ...
queue: steals=... llc=... node=... yield_to=... reweight=... stale=... lost=...
disp: pop=... renew=... total=... q=... path: link_lost=... count_lost=...
unowned: run=... stop=... ...
```

`head_inserts` and `tail_inserts` count all enqueues that pass the 7:1
gate, including wakeups, so their ratio approaches 7:1. `exempt_inserts`
counts only `SCX_ENQ_HEAD` hints. `depth` sums the per-CPU tree depths
when the line is printed.

The cgroup part counts `cpu.max` throttled enqueues and reenqueues. The
weight-library part prints the counters of the shared control map. The
queue part counts steals per tier, yield-to and reweight moves, stale
pops and `lost_state_errors`. The dispatch and path part counts pops,
renewals, the `state_repairs` counter and the reservation counters. A
campaign requires `lost`, `stale`, `link_lost` and
`count_lost` to stay at zero.

## Test harnesses

`scripts/` holds reusable harnesses. They fail closed: a missing tool, a
missing kernel feature, a non-virtual machine or an unreadable file is
BLOCKED, never PASS. Each harness prints one JSON object per line on
stdout and the last line is a summary object. Exit codes are 0 for PASS,
1 for FAIL and 2 for BLOCKED. A check is FAIL only after it ran and
missed its limit.

Every destructive harness needs root, a disposable virtual machine and
an explicit opt-in:

```
export SCX_INFINITY_VM=1
```

Without the variable the harness records a BLOCKED `vm` item and starts
nothing. Never set it on a host you cannot reboot.

The harnesses stop their workers, unload the scheduler and remove their
cgroups on exit, including after a failure. They sample dmesg from the
start of the run and fail on `scx_bpf_error`, a runnable task stall, a
watchdog line or an `Oops`.

The scheduler binary defaults to `target/release/scx_infinity`, then
`target/debug/scx_infinity`. `SCX_INFINITY_BIN` or `--scheduler` selects
another binary. Pass `--out FILE` to keep a copy of the JSON Lines
records.

### Feature preflight

```
sudo scripts/infinity_vm_preflight.sh --json --strict
```

The repository preflight checks `sched_ext`, the BPF arena, the cgroup v2
cpu controller, `cpu.idle` and the sched_ext cgroup callbacks. Strict
mode requires the runtime file, not the kernel configuration alone. The
harness wrapper adds the VM gate. It has no FAIL state: a missing feature
is BLOCKED with exit 2.

```
sudo \
  scheds/experimental/scx_infinity/scripts/infinity_feature_preflight.sh \
  --require-vm [--require-two-numa-nodes]
```

### Cgroup harness

```
SCX_INFINITY_VM=1 sudo \
  scheds/experimental/scx_infinity/scripts/infinity_cgroup_harness.sh \
  [--trials 5] [--cpu 0] [--window 5] [--settle 1] [--out FILE]
```

The harness creates two cgroups and pins one busy worker of each group to
one CPU, so the cases contend. Five trials each cover:

- `cpu.weight` 100:200, expected ratio 1.8 to 2.2.
- A live change from 100:100 to 100:200 after the first window.
- `cpu.idle` 1, then 0, then 1, with progress after the normal worker
  stops.
- `cpu.max` `50000 100000`, expected 45 to 55 percent and a rising
  scheduler throttle counter.
- `cpu.max.burst` 40000 after an underspend, expected a short burst above
  quota.

Every trial record carries the raw `usage_usec` values and the ratio.
The median of each case follows as a `note` record.

### Queue stress

```
SCX_INFINITY_VM=1 sudo \
  scheds/experimental/scx_infinity/scripts/infinity_queue_stress.sh \
  [--duration 8] [--workers N] [--yield-to-cmd CMD] [--out FILE] \
  [--mixed] [--trace] [--test-dsq-refuse N] [--dump-dir DIR]
```

The harness loads the scheduler and runs CPU-bound workers, sleepers next
to burners, fork and exec loops, affinity changes, migrations and
`sched_yield` loops. It then changes the nice value and the cgroup weight
of a running worker and checks the scheduling counters. It stops the
scheduler with SIGINT and checks the exit status, the `disabled` state
and the counters `lost` and `stale`.

Directed yield is reachable from user space only through KVM. Without
`--yield-to-cmd` the `yieldto` item is BLOCKED. A caller with a guest KVM
workload passes the command that triggers the directed yield.

`--mixed` runs every workload class at once for `--duration` and is the
stall campaign. A ten-minute run (`--duration 600`) exercises CPU burn,
sleepers, fork and exec, affinity changes, migrations, `sched_yield`, a
nice change and two live `cpu.weight` writes together. Every worker must
report `done=1` with non-zero CPU time. The run fails on a stall, a
watchdog line, a lost or stale task or a worker that did not progress.

`--trace` loads the scheduler with its diagnostic transition trace. The
trace records the anomalous queue transitions in a 65536-entry ring and
keeps the last eight transitions of every task. The ring counts every
overwrite in `overwritten`, and a non-zero count is a FAIL: the campaign
cannot claim complete transition evidence. `--dump-dir DIR` copies the
scheduler log, dmesg and every worker log out of the temporary directory,
which is needed when a run aborts. `--test-dsq-refuse N` arms N
controlled local-DSQ insert refusals, so the requeue fallback runs
without a kernel refusal. The mixed phase then requires the `requeues`
counter to reach N with `lost=0`.

### Two-node placement

```
SCX_INFINITY_VM=1 sudo \
  scheds/experimental/scx_infinity/scripts/infinity_numa_placement.sh \
  [--duration 2] [--out FILE]
```

The guest must have two online vNUMA nodes. The harness samples the CPU
of a task that wakes on an idle CPU and checks that it stays in the local
LLC and node. It then fills node 0 and expects a wakeup to spill to node
1. It narrows the affinity to node 0 and then to one CPU and requires
zero out-of-mask samples. A sample outside the mask is FAIL.

### Harness self-test

```
scheds/experimental/scx_infinity/scripts/infinity_harness_selftest.sh
```

The self-test needs no root and no scheduler. It covers the JSON, cpulist,
numeric and statistics helpers and checks that each harness rejects an
unknown argument and fails closed on a host.

## Performance status

This tree does not claim performance parity with native Infinity. The
benchmark comparator runs a different kernel, so a cross-kernel result
is directional, not a controlled A/B test. Revision 4 has no numeric
performance regression gate. Correctness is the release gate.

## Requirements

Linux with `sched_ext` enabled (`CONFIG_SCHED_CLASS_EXT`), BPF arena
support, and the sched_ext cgroup callbacks. Run
`scripts/infinity_vm_preflight.sh` in the guest to check them. Build with
`cargo build -p scx_infinity`.

## Deviations from the reference

The reference is the Infinity 7.2.6-7 fair patch. Spec section 2.10
lists the differences in policy, and spec section 2.11 lists the limits
that the verifier and the shared code forced. The ones a user notices:

1. A service slot is one measured kernel tick, not a fixed 1 ms of wall
   time.
2. Preemption is an IPI, so a wake-to-run after a preemption can be
   later by the IPI latency. The check also compares the queue head
   rather than the band winner at every level, so it is stricter.
3. Dispatch does not steal across a NUMA node.
4. A running task observes a weight change at its next tick, at most one
   slot later.
5. An explicit yield charges its reserved slot to the policy ledger while
   `cpu.max` sees only actual runtime.
6. A task in a cgroup deeper than four levels joins its fourth ancestor,
   and the deeper levels carry no share of it.

## Current limitations

- The entity tree holds four cgroup levels. The verifier rejects a
  larger bound, so a deeper cgroup joins the deepest ancestor that has an
  entity. See spec section 2.11, D1.
- A parent queue whose service band holds more than 16 siblings falls
  back to its head. See D2.
- A steal tier probes at most two peers per dispatch. See D3.
- A live `cpu.weight` or `cpu.idle` ratio and the CPU quota cases have no
  PASS record for this revision. The last recorded run measured a weight
  ratio near 1.0 on the guest tick granularity, and that run used a
  revision-3 binary (`.agent/tasks/cgroup-guest-validation/`). Treat a
  share ratio as unverified until a revision-4.1 run records it.
- Placement reads the topology once at load. A CPU set change needs a
  restart. Real hardware and a node hotplug are unverified.
- `cpu.max` is limited to 2048 managed cgroups and 32 levels of nesting
  by the bandwidth library defaults. A larger tree is accounted but the
  excess is not enforced.
- A task in a throttled group is parked in the bandwidth library's arena
  backlog. The scheduler therefore needs arena support from the kernel
  and uses clang 22 or newer, like other arena-based schedulers.
- The arena allocator can refuse a page request under fork churn without
  a scheduler-visible reason. See D6.
- The runnable-task stall is not closed. A successful local DSQ insert
  does not prove the task ran. See D7 and the campaign evidence in
  `.agent/tasks/stall-bisect-rca/` and `.agent/tasks/enq-last-repair/`.
- The previous CPU is reused only when it is idle. The frozen
  specification also allowed a shallow previous queue. This tree keeps
  the stricter locality rule.
- Native RT and DRM GPU scheduling are outside this scheduler. RT,
  deadline and stop tasks keep the kernel classes above sched_ext, and
  GPU work stays with its driver.
