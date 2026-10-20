/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared definitions for scx_infinity.
 *
 * The scheduler keeps one scheduler-owned queue per CPU. A scheduler-owned
 * sequence key gives the queue bounded-LIFO order: a head insert takes the
 * next key below INF_KEY_MID, a tail insert the next key above it, so the
 * queue pops the newest head insert first and a tail insert last. The 7:1
 * gate and the key ranges are fixed. The queue itself is either the EDQ
 * from lib/edq.h or the intrusive FIFO list selected by the queue-list
 * build feature. The base quantum and the placement preferences live in
 * `struct inf_cfg` and a SIGHUP reload replaces them.
 *
 * Placement is locality-first. The loader seeds one topology row per
 * CPU and one NUMA distance row per node, and the scheduler keeps the
 * policy in its own map. No shared helper carries it.
 */
#ifndef __SCX_INFINITY_INTF_H
#define __SCX_INFINITY_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef signed char    s8;
typedef signed short   s16;
typedef signed int     s32;
typedef signed long    s64;
#endif
#include <stdbool.h>

#define INF_QUANTUM_DEFAULT_NS 1000000ULL
#define INF_QUANTUM_MIN_NS 100000ULL
#define INF_QUANTUM_MAX_NS 4000000ULL

/*
 * A task below one tenth of the queue weight gets at least this slice,
 * so a very light task cannot build a sub-microsecond slice. The floor
 * never exceeds the base quantum.
 */
#define INF_QUANTUM_FLOOR_NS 100000ULL

#define INF_PREEMPT_MARGIN_DEFAULT_NS 100000ULL
#define INF_PREEMPT_MARGIN_MAX_NS 1000000ULL
#define INF_STATS_INTERVAL_DEFAULT_MS 1000ULL

/* Copy of SCHED_NORMAL, SCHED_IDLE and SCHED_EXT from uapi/linux/sched.h. */
#define INF_SCHED_NORMAL 0
#define INF_SCHED_IDLE 5
#define INF_SCHED_EXT 7

/* One tail insert in every eight regular enqueues. */
#define INF_GATE_MASK 7U

/*
 * Head keys decrease from INF_KEY_MID and tail keys increase from it.
 * Both runs stay below 2^62 keys in any realistic uptime, so a head key
 * is always before a tail key under the kernel's wrap-safe vtime order.
 */
#define INF_KEY_MID (1ULL << 62)

#define INF_MAX_CPUS 1024
#define INF_MAX_CGROUPS 2048
#define INF_MAX_NODES 64

/* At most eight peers are examined in each dispatch steal tier. */
#define INF_STEAL_SCAN_MAX 8

/*
 * Queue implementation selected at build time. EDQ is the default and the
 * supported integration. The queue-list feature trades the EDQ hold count
 * for an intrusive FIFO list and exists to measure the queue cost.
 */
#define INF_QUEUE_KIND_EDQ 0
#define INF_QUEUE_KIND_LIST 1
#ifdef INF_QUEUE_LIST
#define INF_QUEUE_KIND INF_QUEUE_KIND_LIST
#else
#define INF_QUEUE_KIND INF_QUEUE_KIND_EDQ
#endif

/* Scheduler queue membership and task lifetime states. */
#define INF_TASK_IDLE 0
#define INF_TASK_QUEUED 1
#define INF_TASK_DISPATCHED 2
#define INF_TASK_RUNNING 3
#define INF_TASK_PARKED 4
#define INF_TASK_EXITING 5

/*
 * Arena allocation size for the task context. The real struct embeds the
 * cgroup bandwidth context at offset 0 and one queue node. The loader only
 * needs the size, which a static assertion in main.bpf.c checks.
 */
#define INF_TASK_CTX_SIZE 640

/*
 * One queue node per task. The default node is struct scx_edq_task and
 * the queue-list prototype node is smaller, so the arena layout reserves
 * the size of the selected implementation. Static assertions in
 * main.bpf.c check each implementation against this value.
 */
#ifdef INF_QUEUE_LIST
#define INF_QUEUE_NODE_BYTES 48
#else
#define INF_QUEUE_NODE_BYTES 96
#endif

/* Peer steal tiers and the per-tier scan bound. */
#define INF_STEAL_MAX_PEERS 8
/*
 * Upper bound on the CPU ids one tier walk inspects. The walk stops after
 * eight peers in the tier; this bound keeps the verifier state small on a
 * machine with many CPUs. The cursor carries the walk forward, so a peer
 * outside the window is reached on a later dispatch.
 */
#define INF_STEAL_SCAN_CPUS 64
#define INF_STEAL_LLC 0
#define INF_STEAL_NODE 1

/* Queue node states, mirrored by the Rust model. */
#define INF_TASK_IDLE 0
#define INF_TASK_QUEUED 1
#define INF_TASK_DISPATCHED 2
#define INF_TASK_RUNNING 3
#define INF_TASK_PARKED 4
#define INF_TASK_EXITING 5

/*
 * Arena allocation size for the bandwidth task context. The struct holds
 * struct scx_task_cgroup_bw plus the pid the enqueue callback needs; the
 * extra room keeps the allocation above both and is checked by a static
 * assertion in main.bpf.c.
 */
#define INF_BW_TASK_CTX_SIZE 256

/* A CPU id that cannot name a valid CPU, used for a missing SMT sibling. */
#define INF_NO_CPU 0xffffffffU
/* Distance reported for a node pair that the loader did not seed. */
#define INF_NODE_DISTANCE_FAR 1000U

/* Locality-first placement preferences. */
#define INF_PLACEMENT_AUTO 0U
#define INF_PLACEMENT_LLC 1U
#define INF_PLACEMENT_NUMA 2U
#define INF_PLACEMENT_MACHINE 3U

/*
 * Placement classes, ordered from the best to the worst. The BPF target
 * selection and the pure Rust ranking model share these values.
 */
#define INF_CLASS_IDLE_CORE_LLC 0U
#define INF_CLASS_IDLE_CORE_NODE 1U
#define INF_CLASS_IDLE_CORE_REMOTE 2U
#define INF_CLASS_IDLE_THREAD_LLC 3U
#define INF_CLASS_IDLE_THREAD_NODE 4U
#define INF_CLASS_IDLE_THREAD_REMOTE 5U
#define INF_CLASS_CAPACITY 6U

/*
 * Weight cap. The kernel task weight is at most 10000 and the cgroup
 * share at most 10000, so an effective weight stays below 2^32. Capping
 * there keeps quantum multiplication inside 64 bits without a 128-bit
 * helper in the BPF object.
 */
#define INF_WEIGHT_CAP (1ULL << 32)

/*
 * Live configuration. The loader owns the single array entry and replaces
 * it with one map update, so the BPF side never observes a partial
 * configuration. Queue order and expiry stay compile-time constants.
 */
struct inf_cfg {
	u64 quantum_ns;
	u64 preempt_margin_ns;
	u32 placement_mode;
	u32 smt_enabled;
	u32 spill_threshold;
	u32 generation;
};

struct inf_cpu_ctx {
	u64 head_seq;
	u64 tail_seq;
	u64 w_sum;
	s64 depth;
	u32 seq;
	u32 steal_llc_cursor;
	u32 steal_node_cursor;
	u32 pad;
};

/*
 * Scheduler-local CPU topology, seeded by the loader from
 * scx_utils::Topology before the scheduler is loaded. An entry is valid
 * only when online is 1; an offline CPU keeps zeroed ancestors and is
 * never selected.
 */
struct inf_cpu_topo {
	u32 node_id;
	u32 llc_id;
	u32 core_id;
	u32 sibling_cpu;
	u32 capacity;
	u32 core_primary;
	u32 online;
	u32 head_kflags;
	s64 head_ops_state;
	s32 head_runnable_cpu;
	u32 pad;
};

/* NUMA distance row for one node. The key of the map entry is the node. */
struct inf_node_topo {
	u32 distance[INF_MAX_NODES];
};

/* One slot of the per-task transition history kept in the task context. */
struct inf_hist {
	u32 op;
	s32 src;
	s32 dst;
	s32 result;
	u32 state;
	u32 pad;
};

/*
 * Userspace mirror of the BPF task context size. The real struct embeds
 * `struct scx_task_cgroup_bw` at offset 0, which cannot be exported through
 * this header; only its size is needed to initialize the arena allocator.
 * A static assertion in main.bpf.c keeps the two in sync.
 */
#define INF_CGROUP_BW_CTX_SIZE 120

struct inf_task_ctx_layout {
	u8  cg_bw[INF_CGROUP_BW_CTX_SIZE];
	u8  qnode[INF_QUEUE_NODE_BYTES];
	u64 base_weight;
	u64 weight;
	u64 group_scale;
	u64 slice_ns;
	u64 last_running_ns;
	u64 weight_epoch;
	s32 queued_cpu;
	s32 group_cpu;
	u32 state;
	u32 moving;
	u32 reweight_pending;
	u32 dequeue_pending;
	u32 exit_pending;
	u32 joined;
	u32 yielded;
	u32 wake_fork;
	u32 idle;
	u32 pid;
	u32 hist_idx;
	struct inf_hist hist[8];
};

struct inf_stats {
	u64 head_inserts;
	u64 tail_inserts;
	u64 exempt_inserts;
	u64 expiries;
	u64 preemptions;
	u64 yields;
	u64 cgrp_throttled;
	u64 cgrp_reenqueued;
	u64 cgrp_eff_weight;
	u64 cgrp_eff_min;
	u64 cgrp_eff_max;
	u64 cgrp_eff_samples;
	u64 cgrp_scale;
	u64 cgrp_refolds;
	u64 deq_core_sched_exec;
	u64 deq_sleep;
	u64 deq_sched_change;
	u64 deq_keep;
	u64 q_sleep;
	u64 q_sched_change;
	u64 q_keep;
	u64 cgrp_cpu_moves;
	u64 steals;
	u64 steal_llc;
	u64 steal_node;
	u64 yield_to_moves;
	u64 reweight_moves;
	u64 stale_pops;
	u64 lost_state_errors;
	u64 requeues;
	u64 weight_changes;
	u64 reweight_queued;
	u64 weight_queued_cpu;
	u64 exit_passes;
	u64 enq_no_ctx;
	u64 enq_no_cctx;
	u64 stale_requeues;
	u64 stale_skips;
};

/*
 * Diagnostic trace. The trace is compiled in but disabled unless the
 * loader sets `enable_trace` before load. It records every queue
 * transition that can lose a runnable task, plus one task snapshot that
 * keeps the last transition of each live task. The trace is a ring: once
 * INF_TRACE_CAP records are written the oldest slot is overwritten and
 * `overwritten` counts every replacement. A stall campaign reads the ring
 * and the snapshots from the exit dump.
 */
#define INF_TRACE_CAP 65536
#define INF_TASK_SNAP_MAX 65536

/* One trace operation. The order is stable; the loader names each one. */
#define INF_TR_ENQ_PARK 1
#define INF_TR_ENQ_STALE 2
#define INF_TR_ENQ_INSERT_FAIL 3
#define INF_TR_INSERT 4
#define INF_TR_DEQ_QUEUED 5
#define INF_TR_DEQ_PENDING 6
#define INF_TR_DEQ_REMOVE_FAIL 7
#define INF_TR_DEQ_END 8
#define INF_TR_POP 9
#define INF_TR_POP_STALE 10
#define INF_TR_POP_AFFINITY 11
#define INF_TR_POP_PENDING 12
#define INF_TR_DSQ_OK 13
#define INF_TR_DSQ_REFUSED 14
#define INF_TR_REQUEUE 15
#define INF_TR_REQUEUE_FAIL 16
#define INF_TR_STEAL 17
#define INF_TR_STEAL_SKIP 18
#define INF_TR_REMOVE 19
#define INF_TR_REMOVE_FAIL 20
#define INF_TR_YIELD_TO 21
#define INF_TR_REWEIGHT 22
#define INF_TR_EXIT 23
#define INF_TR_SET_WEIGHT 24
#define INF_TR_DISPATCH_EMPTY 25
#define INF_TR_EXIT_PASS 26

/* The causal fields of one queue transition. */
struct inf_trace_rec {
	u64 ts;
	u64 seq; /* ring sequence number, monotone */
	u64 slice;
	s64 result;
	s32 pid;
	s32 src_cpu; /* source queue, -1 when the task had none */
	s32 dst_cpu; /* target queue, -1 when none */
	u32 op; /* INF_TR_* */
	u32 state; /* enum inf_task_state at the record */
	u32 hold; /* queue node hold count */
	s32 group_cpu;
};

struct inf_trace_ctl {
	u64 next; /* ring records written, including overwritten ones */
	u64 overwritten; /* records replaced in the ring */
	u64 task_overflow; /* task snapshots dropped when the table is full */
	u64 total; /* all transitions seen, ringed or not */
	u32 cap;
	u32 enabled;
};

/* Exit-time queue snapshot, one entry per possible CPU. */
struct inf_queue_snap {
	u64 w_sum;
	u64 head_slice;
	u64 head_weight;
	u64 head_key;
	s64 depth;
	s32 cpu;
	s32 head_pid;
	s32 head_cpu;
	s32 head_group_cpu;
	u32 head_state;
	u32 head_hold;
	u32 online;
	u32 head_kflags;
	s64 head_ops_state;
	s32 head_runnable_cpu;
	u32 pad;
};

/* Exit-time task snapshot, keyed by pid. The last transition is kept. */
struct inf_task_snap {
	u64 ts;
	u64 slice;
	u64 weight;
	s32 pid;
	s32 queued_cpu;
	s32 group_cpu;
	u32 state;
	u32 hold;
	u32 joined;
	u32 moving;
	u32 reweight_pending;
	u32 dequeue_pending;
	u32 exit_pending;
	u32 last_op;
	s32 last_src;
	s32 last_dst;
	s64 last_result;
	u64 prev_ts;
	u32 prev_op;
	u32 prev_state;
	s32 prev_src;
	s32 prev_dst;
	s64 prev_result;
	struct inf_hist hist[8];
	u32 hist_count;
	u32 pad;
};

/* Controlled-refusal counter for the local DSQ insert regression test. */
struct inf_test_ctl {
	u64 dsq_refuse;
};

/*
 * Mirror of lib/cgroup_weight.bpf.c's counter map. A static assertion in
 * main.bpf.c keeps the layout identical to struct
 * scx_cgroup_weight_stats in lib/cgroup_weight.h.
 */
struct inf_cgroup_weight_stats {
	u64 joins;
	u64 leaves;
	u64 reweights;
	u64 moves;
	u64 refolds;
	u64 load_underflows;
	u64 nr_underflows;
	u64 epoch;
	u64 init_idle;
	u64 idle_on;
	u64 idle_off;
};

/* Arguments for the one-shot arena/library init syscall. */
struct inf_arena_init_args {
	u64 static_pages;
	u64 task_ctx_size;
	u64 nr_llcs;
};

#endif /* __SCX_INFINITY_INTF_H */
