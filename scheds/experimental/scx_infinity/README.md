# scx_infinity

Experimental sched_ext scheduler for the Infinity fair policy.

**Status: experimental. Not ready for general use.**

The current tree implements revision 2 of
`.agent/tasks/spec/spec.md`. Revision 3 is the frozen target. It replaces
the per-CPU DSQ queue with a scheduler-owned queue, fixes yield-to,
queued reweight and cpu.weight/cpu.idle, and adds peer dispatch steal.
The code and the tests below do not implement revision 3 yet. The
limitations at the end of this file remain current until they do.

## Scope

The scheduler replaces the fair class for `SCHED_NORMAL`, `SCHED_BATCH`,
`SCHED_IDLE` and `SCHED_EXT` tasks. It enforces `cpu.weight`, `cpu.idle`
and `cpu.max` (quota, period and burst) from cgroup v2. Placement is
locality-first across the previous CPU, the local LLC, the local NUMA
node and a capacity-ranked remote CPU.

Revision 3 specifies one scheduler-owned queue per CPU. A sched_ext
local DSQ runs only the task that the scheduler selected. The ready
queue, its holds and its exact removal stay under scheduler control. The
default queue is `scx_edq` from `scheds/include/lib/edq.h`. A FIFO
intrusive list is a second prototype behind the `queue-list` build
feature. It exists to measure the queue cost. EDQ wins a correctness tie
because it provides a hold count and exact node removal.

The queue choice was measured. Six ten-minute mixed-load campaigns ran
on two restored guests, three per build, with the same configuration and
the same workload. Both builds were correct, with no lost task, no stall
and no lost trace record. Every measured difference was smaller than the
run-to-run spread, so EDQ stays the default and the FIFO list stays a
prototype. The measurement, the selection rule and the rejected
variants are in `.agent/tasks/queue-selection/evidence.md`.

Dispatch in revision 3 steals from same-LLC peer queues first, then from
same-NUMA peers, with a rotating cursor and at most eight peers per
tier. It does not steal across a NUMA node.

Out of scope:

- Native RT, deadline and stop scheduling. The kernel keeps those
  classes above sched_ext, and this scheduler never sees those tasks.
- DRM GPU scheduling. GPU work and the driver runqueues stay outside
  this scheduler.
- A virtual runtime tree, EEVDF lag or deadlines.
- Sub-schedulers, the cid form and `scx_prio`.
- Live CPU hotplug. A CPU set change needs a scheduler restart.

## Overview

`scx_infinity` is a root scheduler that replaces the fair class for
`SCHED_NORMAL`, `SCHED_BATCH`, `SCHED_IDLE` and `SCHED_EXT` tasks. The
scheduler is split into a BPF program in `src/bpf/main.bpf.c` and a Rust
loader in `src/main.rs`.

The core policy is a bounded last-in-first-out queue:

- The current tree uses one vtime-ordered DSQ per CPU. Revision 3 replaces
  it with a scheduler-owned queue per CPU. The key is a scheduler-owned
  sequence, not wall time. Head inserts take the next key below
  `INF_KEY_MID` and tail inserts the next key above it. The queue pops the
  lowest key, so the newest head insert runs first and a tail insert runs
  last. A sched_ext local DSQ then runs only the selected task.
- Eight regular enqueues pass a fixed 7:1 gate. Seven take the head and
  one takes the tail, so at most seven normal arrivals move ahead of a
  queued task between two tail insertions.
- `SCX_ENQ_HEAD` is the only head-exempt hint. sched_ext has no
  equivalent of the kernel's `curr == se` exemption. A wakeup passes the
  same 7:1 gate as any other enqueue and can take the head or the tail
  slot. An expired slice, a requeue, a forced-progress enqueue and a
  yield enter at the tail.
- The slice is `quantum * weight / contending_weight`, with a 100 us
  floor for a task below one tenth of the queue weight. Revision 3
  exempts a `cpu.idle` task from the floor, so its weight of 3 is used as
  is. The contending weight is the sum of the effective weights on the
  target CPU. The slice is recomputed when the task is popped.
- The effective weight folds the cgroup hierarchy in through the shared
  cgroup control library (`lib/cgroup_ctl.bpf.c`). Every nested
  `cpu.weight` level scales the task weight by `shares / load`, and any
  `cpu.idle` group at or above the task uses the `SCHED_IDLE` weight of 3.
  Revision 3 makes the group load follow runnable tasks, not queue
  membership, so a running task stays counted. It also refreshes the
  folded weight at the next enqueue or dispatch after a cgroup change.
- `cpu.max` quota, period and burst come from the existing bandwidth
  library (`lib/cgroup_bw.bpf.c`). A task in a throttled group is parked
  on the library's arena backlog. The library re-enqueues it through the
  same 7:1 gate when the group gets time again.
- A fresh wakeup preempts only when the enqueue took a head slot and the
  victim retains more than the configured preemption margin. The wakeup
  weight is not a condition, so a lighter wakeup preempts a heavier
  victim. A wakeup that took a tail slot does not preempt. Yield
  forfeits the remaining slice and re-enters at the tail. Revision 3 adds
  a two-argument yield that moves a runnable queued target to the head of
  its queue and returns true. It refuses a target that is running, in a
  local DSQ, throttled, exiting or not queued. A task under a `cpu.idle`
  cgroup never preempts.
- Revision 3 also moves a queued task on reweight. The task leaves its
  queue and re-enters through the fixed 7:1 gate, as the reference does.
  Dispatch pops the local queue, then steals the head of a same-LLC peer
  queue, then a same-NUMA peer queue, before it renews the previous task.

The queue order, the 7:1 gate and the slice-expiry rules are fixed. Only
the settings below can change at run time.

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

The loader reads `scx_utils::Topology` and fills a scheduler-local BPF
map with the node, LLC, core, SMT sibling, primary-thread and capacity
data. The placement policy stays in this scheduler. The shared utilities
carry none of it.

Revision 3 adds a second placement point at dispatch. When the local
queue is empty, the CPU steals the head of a same-LLC peer queue, then a
same-NUMA peer queue. Each tier scans at most eight peers from a rotating
cursor. A peer head that cannot run on the stealing CPU is skipped, and
no steal crosses a NUMA node.

## Build

```
cargo build -p scx_infinity
```

The BPF object needs clang 22 or newer and a kernel built with
`CONFIG_SCHED_CLASS_EXT`. The scheduler uses the BPF arena and the
shared cgroup libraries. Revision 3 also needs BPF arena support and the
sched_ext cgroup callbacks. The VM preflight checks both:

```
sudo ./scripts/infinity_vm_preflight.sh
```

The default queue is EDQ. The FIFO measurement prototype builds with:

```
cargo build -p scx_infinity --features queue-list
```

The FIFO prototype stays a measurement prototype. The measured
comparison found no gain over the run-to-run noise, so it is not the
default.

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
scx_infinity [--config PATH] [--exit-dump-len N] [--quantum-us N]
             [--placement MODE] [--no-smt] [--spill-threshold N]
             [--preempt-margin-us N] [--no-cpu-max] [--verbose] [--version]
             [--trace] [--test-dsq-refuse N]
```

- `--config PATH`: read this TOML file instead of the default XDG path.
- `--exit-dump-len N`: exit debug dump buffer length, 0 selects the
  default.
- `--quantum-us N`: base quantum in microseconds, 100 to 4000, default
  1000 (1 ms). Overrides the file.
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
- `--trace`: diagnostic only. Record queue transitions and the last eight
  transitions of every task, and print the trace ring, the per-CPU queue
  snapshot and the task snapshot when the scheduler exits. The trace is
  off by default. A trace record carries the operation, the task id, the
  source and destination CPU, the queue state, the node hold count, the
  group CPU, the slice and the result.
- `--test-dsq-refuse N`: diagnostic only, hidden. Refuse the first N
  local DSQ inserts without calling the kernel, so the requeue fallback
  runs deterministically.

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
quantum_ns = 1000000        # 100_000 ..= 4_000_000
placement = "auto"          # "auto" | "llc" | "numa" | "machine"
smt = true                  # false: physical cores only
preempt_margin_ns = 100000  # 0 ..= 1_000_000
spill_threshold = 4         # 1 ..= 64
stats_interval_ms = 1000    # 0 disables the stats line
```

The file is checked as a whole before any value is applied. All errors
are reported in one message, and a rejected file changes nothing.

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

The loader prints one line per second:

```
inserts: head=... tail=... exempt=... expiries=... preemptions=... yields=... depth=...
cgrp: throttled=... reenqueued=... eff_weight=... scale_q10=...
```

`head_inserts` and `tail_inserts` count all enqueues that pass the 7:1
gate, including wakeups, so their ratio approaches 7:1. `exempt_inserts`
counts only `SCX_ENQ_HEAD` hints, expiries, requeues and forced progress.
`depth` sums the per-CPU queue depths when the line is printed.

The cgroup part counts `cpu.max` throttled enqueues and reenqueues, and
reports the largest effective group weight and folded group scale seen on
any CPU. `scale_q10` is the shares/load product in 1/1024 units.

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
- `cpu.max` `50000 100000`, expected 45 to 55 percent and rising
  `nr_throttled` and `throttled_usec`.
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
stall campaign: a ten-minute run (`--duration 600`) exercises CPU burn,
sleepers, fork and exec, affinity changes, migrations, `sched_yield`, a
nice change and two live `cpu.weight` writes together. Every worker must
report `done=1` with non-zero CPU time, and the run fails on a stall, a
watchdog line, a lost or stale task or a worker that did not progress.

`--trace` loads the scheduler with its diagnostic transition trace. The
trace records the anomalous queue transitions in a 65536-entry ring and
keeps the last eight transitions of every task. The ring counts every
overwrite in `overwritten`, and a non-zero count is a FAIL: the campaign
cannot claim complete transition evidence. `--dump-dir DIR` copies the
scheduler log, dmesg and every worker log out of the temporary directory,
which is needed when a run aborts. `--test-dsq-refuse N` arms N
controlled local-DSQ insert refusals, so the requeue fallback runs
without a kernel refusal; the mixed phase then requires the `requeues`
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
is directional, not a controlled A/B test. Revision 3 has no numeric
performance regression gate. Correctness is the release gate. The EDQ
default and the FIFO prototype are measured only to choose between them.
A performance difference alone does not change the default unless the
FIFO prototype also passes every case.

## Unverified: multi-node NUMA

The placement code reads the node distance matrix, ranks remote nodes
and places tasks across nodes. Only a single-node host ran this
scheduler. Revision 3 adds a two-node vNUMA VM test plan. It includes
the preflight, the local-first placement check and the rule that a steal
never crosses a node. Real hardware and a node hotplug remain unverified.

## Requirements

Linux with `sched_ext` enabled (`CONFIG_SCHED_CLASS_EXT`), BPF arena
support, and the sched_ext cgroup callbacks. Run
`scripts/infinity_vm_preflight.sh` in the guest to check them. Build with
`cargo build -p scx_infinity`. The FIFO prototype needs the `queue-list`
Cargo feature.

## Deviations from the reference

The reference is the Infinity 7.2.6-7 fair patch. These are the
behaviors of the current revision 2 tree. Revision 3 specifies the fix
for the first three and for the cgroup gap in the last item. The fixes
are not implemented yet:

1. Two-argument yield does not move a queued target to the head. The
   donor forfeits its slice and rotates to the tail, and the target
   keeps its queue position. Revision 3 replaces this with a target
   remove and a head insert. See spec section 2.5.
2. A queued task keeps its DSQ position on reweight. The new weight
   changes the contending weight and the next slice, not the current
   position. Revision 3 replaces this with a remove and a reinsert
   through the 7:1 gate. See spec section 2.6.
3. Dispatch does not spill from peer LLC or node DSQs. Placement picks
   the target CPU at enqueue and the task waits on that CPU's DSQ. A
   busy CPU does not move its queued work to an idle peer at dispatch.
   Revision 3 adds same-LLC and same-NUMA peer steal. See spec section
   4.2.
4. Group load is not decayed, and live `cpu.weight` and `cpu.idle`
   ratios remain unverified. A group that becomes empty updates on its
   next member, and until then a stale load can under-credit it.
   Revision 3 keeps runnable group load separate from queue membership.
   It handles the dequeue flags distinctly. It refreshes the effective
   weight at the next enqueue or dispatch. See spec section 5.

## Current limitations

- The cgroup hierarchy is folded into one effective weight per task, as
  `scx_eevdf` does with a single runqueue. Nested shares multiply
  correctly, but the exact per-level ordering of the kernel hierarchy is
  not reproduced. A cgroup deeper than 32 levels uses its bottom 32
  levels, the cgroup v2 cap.
- A live `cpu.weight` or `cpu.idle` ratio has not been demonstrated. In
  the integration smoke run, groups at weight 100 and 200, and also a
  `cpu.idle` group against a normal group, received equal shares. The
  reported effective weight also reached 1000000. Revision 3 records the
  causes. A running task left the group load. A zero load could scale a
  task up without bound. A queued or running task never refreshed its
  fold. The five-run VM tests in spec section 7.4 are the acceptance
  gate. `cpu.max` does hold a 50 ms / 100 ms group near 50 percent.
- Placement reads the topology once at load. A CPU set change needs a
  restart. Multi-node behavior is written for several nodes and the
  revision 3 VM plan tests two nodes, but real hardware is unverified.
- Dispatch does not steal across a NUMA node. A node with more runnable
  tasks than CPUs can leave a remote node idle. See spec section 9.
- `cpu.max` is limited to 2048 managed cgroups and 32 levels of nesting
  by the bandwidth library defaults. A larger tree is accounted but the
  excess is not enforced.
- A task in a throttled group is parked in the bandwidth library's arena
  backlog. The scheduler therefore needs arena support from the kernel
  and uses clang 22 or newer, like other arena-based schedulers.
- A queued task whose group weight or idle state changes keeps a stale
  contribution in the queue weight sum until it is dispatched. The error
  is bounded by one task weight and one round. See spec section 5.1.
- A CPU set or topology change requires a scheduler restart.
- The previous CPU is reused only when it is idle. The frozen
  specification also allowed a shallow previous queue. This tree keeps
  the stricter locality rule.
- Native RT and DRM GPU scheduling are outside this scheduler. RT,
  deadline and stop tasks keep the kernel classes above sched_ext, and
  GPU work stays with its driver.
