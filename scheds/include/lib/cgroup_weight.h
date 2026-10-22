/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Group-weight part of the shared cgroup control API.
 *
 * A scheduler that wants hierarchical cpu.weight and cpu.idle calls the
 * callbacks below from its cgroup ops and the accounting helpers from its
 * enqueue, dequeue and reweight paths. The library keeps one load per
 * (cgroup, CPU) and folds the hierarchy into one effective task weight, the
 * same single-runqueue model scx_eevdf uses.
 *
 * A scheduler that owns the hierarchy itself, one node per (cgroup, CPU),
 * reads the stored control state with scx_cgroup_weight_node() instead of
 * calling the fold. That accessor is read-only: it returns what the cgroup
 * callbacks stored and changes no load, count, epoch or fold result.
 *
 * The bandwidth half of the API stays in lib/cgroup.h. A scheduler that
 * wants both includes lib/cgroup_ctl.h.
 */
#pragma once

#ifndef __VMLINUX_H__
typedef unsigned long u64;
typedef signed int    s32;
#endif
#include <stdbool.h>

struct cgroup;
struct task_struct;
struct scx_cgroup_init_args;

/* Deepest hierarchy the library accounts for. cgroup v2 caps depth at 32. */
#define SCX_CGROUP_WEIGHT_MAX_DEPTH 32

/* Fixed-point bits of the folded shares/load product. */
#define SCX_CGROUP_WEIGHT_SHIFT 10
#define SCX_CGROUP_WEIGHT_ONE (1ULL << SCX_CGROUP_WEIGHT_SHIFT)

/* SCHED_IDLE weight, used for a task under a cpu.idle cgroup. */
#define SCX_CGROUP_WEIGHT_IDLE 3

/* Pin the static map sizes so the loader can rely on them. */
#define SCX_CGROUP_WEIGHT_NR_CGRP_MAX 4096
#define SCX_CGROUP_WEIGHT_NR_CPU_ENTRIES 65536

/* Upper bound of the per-CPU contribution sync on a shares change. */
#define SCX_CGROUP_WEIGHT_MAX_CPUS 1024

struct scx_cgroup_weight_config {
	int verbose;
};

/*
 * Accounting counters. @joins and @leaves bracket a task's runnable
 * period, @reweights counts a nice-weight change, @refolds counts a task
 * that refolded after an epoch change, and @load_underflows counts a
 * subtract that would have driven a per-CPU load or task count below
 * zero. @epoch is the value of the last change.
 */
struct scx_cgroup_weight_stats {
	u64 joins;
	u64 leaves;
	u64 reweights;
	u64 moves;
	u64 refolds;
	u64 load_underflows;
	u64 nr_underflows;
	u64 epoch;
	/* Groups that arrived already idle and live idle changes. */
	u64 init_idle;
	u64 idle_on;
	u64 idle_off;
};

/*
 * Result of folding the hierarchy for one task on one CPU.
 *
 * @weight: effective weight, ready for the scheduler's quantum
 * @scale:  the folded shares/load product, in SCX_CGROUP_WEIGHT_ONE units
 * @idle:   1 when a cpu.idle group is at or above the task
 */
struct scx_cgroup_weight_info {
	u64 weight;
	u64 scale;
	u32 idle;
	u32 pad;
};

/*
 * Read-only control state of one cgroup, for a scheduler that builds its own
 * per-CPU hierarchy.
 *
 * @cgrp_id:   kernel control-group id, as stored in cgrp->kn->id
 * @parent_id: nearest ancestor that has a control entry, 0 at the root
 * @epoch:     the library epoch when the value was read, see
 *             scx_cgroup_weight_epoch()
 * @weight:    cpu.weight, 0 when the group is not present
 * @idle:      cpu.idle, 0 when the group is not present
 * @present:   1 when the cgroup has a live control entry at its level
 *
 * Identity and control values are the same on every CPU. The CPU argument of
 * scx_cgroup_weight_node() names the coordinate the caller is building a node
 * for, and only bounds-checks that coordinate.
 *
 * The process root cgroup, a cgroup without the cpu controller, and a cgroup
 * that has exited report @present 0 with @weight, @idle and @parent_id 0.
 * A caller that needs the root's own weight uses its task weight, because
 * fair.c scales nothing at the root.
 */
struct scx_cgroup_weight_node {
	u64 cgrp_id;
	u64 parent_id;
	u64 epoch;
	u32 weight;
	u32 idle;
	u32 present;
	u32 pad;
};

int  scx_cgroup_weight_lib_init(struct scx_cgroup_weight_config *config);

int  scx_cgroup_weight_init(struct cgroup *cgrp		      __arg_trusted,
			    struct scx_cgroup_init_args *args __arg_trusted);
void scx_cgroup_weight_exit(struct cgroup *cgrp __arg_trusted);
void scx_cgroup_weight_set_weight(struct cgroup *cgrp __arg_trusted,
				  u32		      weight);
void scx_cgroup_weight_set_idle(struct cgroup *cgrp __arg_trusted, bool idle);

/*
 * Effective weight of @p on @cpu. With @joining, @p is about to become
 * runnable there and its own weight and the shares of the empty groups it
 * joins are counted in, so the result matches the loads after
 * scx_cgroup_weight_join().
 */
int scx_cgroup_weight_task(struct task_struct *p __arg_trusted, s32 cpu,
			   bool joining, struct scx_cgroup_weight_info *out);

/*
 * Fold the hierarchy of @cgrp for a task of @base_weight. The cgroup_move
 * op uses this with the destination cgroup, because the task's own cgroup
 * pointer can still name the source at that point.
 */
int scx_cgroup_weight_fold(struct cgroup *cgrp __arg_trusted, s32 cpu,
			   u64 base_weight, bool joining,
			   struct scx_cgroup_weight_info *out);

/* Epoch of the last weight or idle change. */
u64 scx_cgroup_weight_epoch(void);

/*
 * Fill @out with the control state of @cgrp for @cpu. Read-only: no load,
 * count, epoch or fold value changes. Returns 0 on success, including when
 * the group is not present, which @out->present reports. Returns -EINVAL on
 * a NULL argument or a negative CPU.
 */
int scx_cgroup_weight_node(struct cgroup *cgrp __arg_trusted, s32 cpu,
			   struct scx_cgroup_weight_node *out);

/* Refold an already joined task after an epoch change. */
int scx_cgroup_weight_refresh(struct task_struct *p __arg_trusted, s32 cpu,
			      u64			     base_weight,
			      struct scx_cgroup_weight_info *out);

/*
 * Account @base_weight of @p at @cpu. @join and @leave are paired across the
 * task's runnable period; @reweight moves only the task's own contribution
 * after a nice change.
 */
void scx_cgroup_weight_join(struct task_struct *p __arg_trusted, s32 cpu,
			    u64 base_weight);
void scx_cgroup_weight_leave(struct task_struct *p __arg_trusted, s32 cpu,
			     u64 base_weight);
void scx_cgroup_weight_reweight(struct task_struct *p __arg_trusted, s32 cpu,
				u64 old_weight, u64 new_weight);

/*
 * Move @base_weight from @from to @to. The cgroup_move op passes the two
 * cgroups directly, so it does not depend on when the task's cgroup pointer
 * changes.
 */
void scx_cgroup_weight_move(struct cgroup *from __arg_trusted,
			    struct cgroup *to __arg_trusted, s32 cpu,
			    u64 base_weight);
