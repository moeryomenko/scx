/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared definitions for scx_infinity.
 *
 * The scheduler keeps one vtime-ordered DSQ per CPU. A scheduler-owned
 * sequence key gives the DSQ bounded-LIFO order: a head insert takes the
 * next key below INF_KEY_MID, a tail insert the next key above it, so the
 * ascending vtime order pops the newest head insert first and a tail
 * insert last. The 7:1 gate and the key ranges are fixed. The base
 * quantum and the placement preferences live in `struct inf_cfg` and a
 * SIGHUP reload replaces them.
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
	u32 pad;
};

/* NUMA distance row for one node. The key of the map entry is the node. */
struct inf_node_topo {
	u32 distance[INF_MAX_NODES];
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
	u64 base_weight;
	u64 weight;
	u64 group_scale;
	u64 slice_ns;
	u64 last_running_ns;
	s32 queued_cpu;
	s32 group_cpu;
	u32 joined;
	u32 yielded;
	u32 wake_fork;
	u32 idle;
	u32 pid;
	u32 pad;
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
	u64 cgrp_scale;
};

/*
 * Mirror of the shared cgroup library counters, read from
 * scx_cgroup_global_stor and scx_cgroup_weight_stor. A static assertion
 * in main.bpf.c keeps the layout identical to lib/cgroup_weight.h.
 */
struct inf_cgroup_global_stats {
	u64 throttle_events;
	s64 nr_throttled_groups;
	u64 nr_cgroups;
};

struct inf_cgroup_weight_stats {
	u64 samples;
	u64 sum;
	u64 min;
	u64 max;
};

/* Arguments for the one-shot arena/library init syscall. */
struct inf_arena_init_args {
	u64 static_pages;
	u64 task_ctx_size;
	u64 nr_llcs;
};

#endif /* __SCX_INFINITY_INTF_H */
