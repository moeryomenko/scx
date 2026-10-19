# scx_infinity

Experimental sched_ext scheduler and skeleton for the Infinity policy.

**Status: experimental. Not ready for general use.** This build is a global
FIFO and does not implement the Infinity policy.

## Overview

`scx_infinity` is a root scheduler that replaces the fair class for
`SCHED_NORMAL`, `SCHED_BATCH`, `SCHED_IDLE` and `SCHED_EXT` tasks. The
scheduler is split into a BPF program in `src/bpf/main.bpf.c` and a Rust
loader in `src/main.rs`, in the same shape as the other schedulers in this
repository.

The current build is a loading and teardown skeleton:

- `ops.select_cpu` asks `scx_bpf_select_cpu_dfl` for a target CPU and
  inserts the task into that CPU's local DSQ when the selection is direct.
- `ops.enqueue` inserts every other task into `SCX_DSQ_GLOBAL` with
  `SCX_SLICE_DFL`.
- `ops.init` returns 0, and `ops.exit` records the exit kind through
  `UEI_DEFINE`.

The global DSQ is FIFO, so the effective policy is global first in, first
out. A `uei` exit reason is printed when the scheduler stops.

## Usage

```
scx_infinity [--exit-dump-len N] [--verbose] [--version]
```

- `--exit-dump-len N`: exit debug dump buffer length, 0 selects the
  default.
- `--verbose`: enable libbpf and loader diagnostics.
- `--version`: print the scheduler version and exit.

Run it as root. Press Ctrl-C to unregister the scheduler.

## Requirements

Linux with `sched_ext` enabled (`CONFIG_SCHED_CLASS_EXT`). Build with
`cargo build -p scx_infinity`.

## Current limitations

- The Infinity policy is not implemented. There is no bounded last-in-first-out
  queue, no 7:1 insertion gate, no weighted quantum, no slice renewal, no
  wakeup preemption, no yield or reweight handling, and no group weight.
- All work shares one global FIFO. There is no locality placement, no per-CPU
  or per-node queue, no dispatch spill and no capacity ranking.
- Cgroup controls are not implemented: `cpu.weight`, `cpu.idle` and
  `cpu.max` have no effect.
- The slice is fixed at `SCX_SLICE_DFL`. There is no configuration file, no
  SIGHUP reload and no statistics or monitoring server.
- RT, deadline and stop tasks are not scheduled by this scheduler. The
  kernel keeps those classes above sched_ext.
- A CPU set or topology change requires a scheduler restart.
