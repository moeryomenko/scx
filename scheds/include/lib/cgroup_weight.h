/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Stored cpu.weight and cpu.idle of a cgroup, for the shared cgroup API.
 *
 * The library owns the control state of a cgroup: the cpu.weight, the
 * cpu.idle flag and the change epoch. A scheduler that owns its own
 * hierarchy, one entity per (cgroup, CPU), reads that state with
 * scx_cgroup_weight_node() and does the weighting itself.
 *
 * The accessor is read-only: it returns what the cgroup callbacks stored and
 * changes no epoch. There is no folded weight in this library, so no
 * per-CPU load, no join/leave/reweight accounting and no move helper.
 *
 * The bandwidth half of the API is lib/cgroup.h. A scheduler that uses both
 * includes both headers.
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

/* SCHED_IDLE weight, used for a task under a cpu.idle cgroup. */
#define SCX_CGROUP_WEIGHT_IDLE 3

/* Pin the map size so the loader can rely on it. */
#define SCX_CGROUP_WEIGHT_NR_CGRP_MAX 4096

struct scx_cgroup_weight_config {
	int verbose;
};

/*
 * Accounting counters. @init_idle counts a group that arrived idle, and
 * @idle_on and @idle_off count live cpu.idle changes. @epoch is the value of
 * the last change.
 *
 * @joins, @leaves, @reweights, @moves, @refolds, @load_underflows and
 * @nr_underflows belonged to the removed fold accounting. They stay in the
 * layout, at zero, because a reader of the map still consumes them.
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

/* Epoch of the last weight or idle change. */
u64 scx_cgroup_weight_epoch(void);

/*
 * Fill @out with the control state of @cgrp for @cpu. Read-only: no epoch
 * moves. Returns 0 on success, including when the group is not present,
 * which @out->present reports. Returns -EINVAL on a NULL argument or a
 * negative CPU.
 */
int scx_cgroup_weight_node(struct cgroup *cgrp __arg_trusted, s32 cpu,
			   struct scx_cgroup_weight_node *out);
