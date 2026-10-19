/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared definitions for scx_infinity.
 *
 * The scheduler keeps one vtime-ordered DSQ per CPU. A scheduler-owned
 * sequence key gives the DSQ bounded-LIFO order: a head insert takes the
 * next key below INF_KEY_MID, a tail insert the next key above it, so the
 * ascending vtime order pops the newest head insert first and a tail
 * insert last. The 7:1 gate and the key ranges are fixed; only the base
 * quantum is a startup setting.
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

/*
 * Weight cap. The kernel task weight is at most 10000 and the cgroup
 * share at most 10000, so an effective weight stays below 2^32. Capping
 * there keeps quantum multiplication inside 64 bits without a 128-bit
 * helper in the BPF object.
 */
#define INF_WEIGHT_CAP (1ULL << 32)

/*
 * A victim that has less than one eighth of the configured quantum left
 * is about to expire, so it finishes instead of taking a preemption IPI.
 */
#define INF_PREEMPT_DIV 8ULL

struct inf_cpu_ctx {
	u64 head_seq;
	u64 tail_seq;
	u64 w_sum;
	s64 depth;
	u32 seq;
	u32 pad;
};

struct inf_task_ctx {
	u64 weight;
	u64 group_scale;
	u64 cgid;
	u64 slice_ns;
	s32 queued_cpu;
	u32 yielded;
	u32 wake_fork;
	u32 idle;
};

struct inf_cgrp_ctx {
	u64 weight;
	u64 idle;
};

struct inf_stats {
	u64 head_inserts;
	u64 tail_inserts;
	u64 exempt_inserts;
	u64 expiries;
	u64 preemptions;
	u64 yields;
};

#endif /* __SCX_INFINITY_INTF_H */
