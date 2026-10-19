# scx_infinity

Experimental sched_ext scheduler for the Infinity fair policy.

**Status: experimental. Not ready for general use.**

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
- The slice is `quantum * weight / contending_weight`, with a 1 ns floor.
  The contending weight is the sum of the effective weights on the target
  CPU. The slice is recomputed when the task is popped.
- The effective weight is the kernel task weight scaled by the cgroup
  `cpu.weight` when the running kernel exposes `scx_bpf_task_cgroup()`.
  A cgroup in `cpu.idle` mode gets the `SCHED_IDLE` weight of 3.
- A fresh wakeup preempts only when it is heavier than the running task
  and the victim retains at least one preemption reserve of the quantum.
  Yield forfeits the remaining slice and re-enters at the tail.

## Usage

```
scx_infinity [--exit-dump-len N] [--quantum-us N] [--verbose] [--version]
```

- `--exit-dump-len N`: exit debug dump buffer length, 0 selects the
  default.
- `--quantum-us N`: base quantum in microseconds, 100 to 4000, default
  1000 (1 ms).
- `--verbose`: enable libbpf and loader diagnostics.
- `--version`: print the scheduler version and exit.

Run it as root. Press Ctrl-C to unregister the scheduler.

## Statistics

The loader prints one line per second:

```
inserts: head=... tail=... exempt=... expiries=... preemptions=... yields=... depth=...
```

`head_inserts` and `tail_inserts` count only regular gated enqueues, so
their ratio approaches 7:1. `exempt_inserts` counts wakeups, core head
hints, expiries, requeues and forced progress. `depth` sums the per-CPU
queue depths when the line is printed.

## Requirements

Linux with `sched_ext` enabled (`CONFIG_SCHED_CLASS_EXT`). Build with
`cargo build -p scx_infinity`.

## Current limitations

- The cgroup weight is applied per task, not through a per-cgroup load
  normalizer. Nested groups multiply their shares, but the exact
  per-level ordering of the kernel hierarchy is not reproduced.
- Multi-node placement is not implemented. Tasks wait on the CPU chosen
  by `scx_bpf_select_cpu_dfl`.
- Cgroup bandwidth (`cpu.max`) is not linked yet. Only `cpu.weight` and
  `cpu.idle` affect the effective weight.
- A cgroup weight change affects a queued task at its next enqueue or
  dispatch. A running task keeps the slice it started with.
- A CPU set or topology change requires a scheduler restart.
- RT, deadline and stop tasks are not scheduled by this scheduler. The
  kernel keeps those classes above sched_ext.
