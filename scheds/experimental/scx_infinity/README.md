# scx_infinity

Experimental sched_ext scheduler for the Infinity fair policy.

**Status: experimental. Not ready for general use.**

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

## Overview

`scx_infinity` is a root scheduler that replaces the fair class for
`SCHED_NORMAL`, `SCHED_BATCH`, `SCHED_IDLE` and `SCHED_EXT` tasks. The
scheduler is split into a BPF program in `src/bpf/main.bpf.c` and a Rust
loader in `src/main.rs`.

The core policy is a bounded last-in-first-out queue:

- One vtime-ordered DSQ per CPU holds runnable tasks. The key is a
  scheduler-owned sequence, not wall time. Head inserts take the next key
  below `INF_KEY_MID` and tail inserts the next key above it. The kernel
  pops the lowest key, so the newest head insert runs first and a tail
  insert runs last.
- Eight regular enqueues pass a fixed 7:1 gate. Seven take the head and
  one takes the tail, so at most seven normal arrivals move ahead of a
  queued task between two tail insertions.
- A fresh wakeup is exempt and enters at the head. An expired slice, a
  requeue, a forced-progress enqueue and a yield enter at the tail.
- The slice is `quantum * weight / contending_weight`, with a 100 us
  floor for a task below one tenth of the queue weight. The contending
  weight is the sum of the effective weights on the target CPU. The
  slice is recomputed when the task is popped.
- The effective weight folds the cgroup hierarchy in through the shared
  cgroup control library (`lib/cgroup_ctl.bpf.c`). Every nested
  `cpu.weight` level scales the task weight by `shares / load`, and any
  `cpu.idle` group at or above the task uses the `SCHED_IDLE` weight of 3.
- `cpu.max` quota, period and burst come from the existing bandwidth
  library (`lib/cgroup_bw.bpf.c`). A task in a throttled group is parked
  on the library's arena backlog and re-enqueued through the same 7:1
  gate when the group gets time again.
- A fresh wakeup preempts only when it is heavier than the running task
  and the victim retains at least the configured preemption margin.
  Yield forfeits the remaining slice and re-enters at the tail. A task
  under a `cpu.idle` cgroup never preempts.

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
data. The placement policy stays in this scheduler; the shared utilities
carry none of it.

## Build

```
cargo build -p scx_infinity
```

The BPF object needs clang 22 or newer and a kernel built with
`CONFIG_SCHED_CLASS_EXT`. The scheduler uses the BPF arena and the
shared cgroup libraries. For a release binary:

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
- `--no-cpu-max`: do not enforce `cpu.max`; `cpu.weight` and `cpu.idle`
  stay active. A kernel without `ops.cgroup_set_bandwidth()` disables the
  same path automatically.
- `--verbose`: enable libbpf and loader diagnostics.
- `--version`: print the scheduler version and exit.

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

The file is validated as a whole before any value is applied. All errors
are reported in one message, and a rejected file changes nothing.

## Reload

Send `SIGHUP` to reread the same path:

```
kill -HUP $(pidof scx_infinity)
```

The loader parses and validates the new file, applies the command-line
overrides again, and publishes the result with one BPF map update. An
override therefore persists across a reload. If parsing or validation
fails, the error is logged, the active settings stay live, and the
scheduler keeps running. The queue order and expiry mechanics never
change on reload.

## Statistics

The loader prints one line per second:

```
inserts: head=... tail=... exempt=... expiries=... preemptions=... yields=... depth=...
cgrp: throttled=... reenqueued=... eff_weight=... scale_q10=...
```

`head_inserts` and `tail_inserts` count only regular gated enqueues, so
their ratio approaches 7:1. `exempt_inserts` counts wakeups, core head
hints, expiries, requeues and forced progress. `depth` sums the per-CPU
queue depths when the line is printed.

The cgroup part counts `cpu.max` throttled enqueues and reenqueues, and
reports the largest effective group weight and folded group scale seen on
any CPU. `scale_q10` is the shares/load product in 1/1024 units.

## Performance status

This tree does not claim performance parity with native Infinity. The
benchmark comparator runs a different kernel, so a cross-kernel result
is directional, not a controlled A/B test. The benchmark rerun is a
separate gate and is not part of this tree.

## Unverified: multi-node NUMA

The placement code reads the node distance matrix, ranks remote nodes
and spills across nodes. Only a single-node host has run this
scheduler. Two-node behavior, cross-node spill and the seeded distance
values are unverified until a multi-node host runs the smoke and
benchmark suites.

## Requirements

Linux with `sched_ext` enabled (`CONFIG_SCHED_CLASS_EXT`). Build with
`cargo build -p scx_infinity`.

## Current limitations

- The cgroup hierarchy is folded into one effective weight per task, as
  `scx_eevdf` does with a single runqueue. Nested shares multiply
  correctly, but the exact per-level ordering of the kernel hierarchy is
  not reproduced. A cgroup deeper than 32 levels uses its bottom 32
  levels, the cgroup v2 cap.
- Group loads are not decayed. A group that becomes empty updates on its
  next member, which can under-credit it briefly. This affects fairness,
  not safety.
- A live `cpu.weight` or `cpu.idle` ratio has not been demonstrated. In
  the integration smoke run, groups at weight 100 and 200, and also a
  `cpu.idle` group against a normal group, received equal shares on one
  CPU. The reported effective weight also reached 1000000. The folded
  arithmetic is unit-tested, but the BPF weight path needs a controlled
  runtime check. `cpu.max` does hold a 50 ms / 100 ms group near
  50 percent.
- Placement reads the topology once at load. A CPU set change needs a
  restart, and multi-node behavior is written for several nodes but has
  only been checked on a single-node host.
- `cpu.max` is limited to 2048 managed cgroups and 32 levels of nesting
  by the bandwidth library defaults. A larger tree is accounted but the
  excess is not enforced.
- A task in a throttled group is parked in the bandwidth library's arena
  backlog. The scheduler therefore needs arena support from the kernel
  and uses clang 22 or newer, like other arena-based schedulers.
- A cgroup weight change affects a queued task at its next enqueue or
  dispatch. A running task keeps the slice it started with.
- A CPU set or topology change requires a scheduler restart.
- The previous CPU is reused only when it is idle. The frozen
  specification also allowed a shallow previous queue. This tree keeps
  the stricter locality rule.
- Native RT and DRM GPU scheduling are outside this scheduler. RT,
  deadline and stop tasks keep the kernel classes above sched_ext, and
  GPU work stays with its driver.
