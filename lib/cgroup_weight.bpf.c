/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * The stored cpu.weight and cpu.idle of a cgroup.
 *
 * The library keeps one control entry per cgroup and hands it to the
 * scheduler that owns the hierarchy. A scheduler that builds its own
 * per-(cgroup, CPU) entities reads the entry with
 * scx_cgroup_weight_node() and does the weighting itself: there is no
 * folded weight, no per-CPU load and no accounting helper here.
 *
 * A change of either file bumps one library-wide epoch, so a scheduler can
 * tell an unchanged entry from a changed one without comparing every field.
 */
#include <scx/common.bpf.h>
#include <lib/cgroup_weight.h>

#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif
#ifndef max
#define max(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

struct scw_group {
	u64 weight; /* cpu.weight, tg->shares */
	u64 parent_id; /* nearest ancestor with a context, 0 at root */
	u32 level;
	u32 idle; /* cpu.idle */
	u32 present;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct scw_group);
	__uint(max_entries, SCX_CGROUP_WEIGHT_NR_CGRP_MAX);
} scw_groups SEC(".maps");

/*
 * Per-CPU counters. A shares or idle change bumps @epoch once, and a
 * scheduler that latched the old epoch sees a different value at its next
 * enqueue or dispatch. The counters make a lifecycle bug visible instead of
 * a silent share error.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scx_cgroup_weight_stats);
} scw_stats_stor SEC(".maps");

/* Global change counter. A scheduler compares this value across slots. */
static u64					       scw_epoch;

static __always_inline struct scx_cgroup_weight_stats *scw_stats(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&scw_stats_stor, &key);
}

#define SCW_STAT_INC(field)                                            \
	do {                                                           \
		struct scx_cgroup_weight_stats *__stats = scw_stats(); \
		if (__stats)                                           \
			__sync_fetch_and_add(&__stats->field, 1);      \
	} while (0)

static __always_inline void scw_epoch_bump(void)
{
	struct scx_cgroup_weight_stats *stats = scw_stats();
	u64				epoch;

	epoch = __sync_fetch_and_add(&scw_epoch, 1) + 1;
	if (stats)
		WRITE_ONCE(stats->epoch, epoch);
}

__hidden u64 scx_cgroup_weight_epoch(void)
{
	return READ_ONCE(scw_epoch);
}

static __always_inline u64 scw_cgroup_id(struct cgroup *cgrp)
{
	return BPF_CORE_READ(cgrp, kn, id);
}

/*
 * @cgrp's ancestor at @ancestor_level. Ancestors outlive their descendants,
 * so a caller holding a live task's cgroup pins the result; no reference is
 * taken.
 */
static __always_inline struct cgroup *scw_cgroup_ancestor(struct cgroup *cgrp,
							  int ancestor_level)
{
	if (ancestor_level < 0 || ancestor_level > BPF_CORE_READ(cgrp, level))
		return NULL;

	return BPF_CORE_READ(cgrp, ancestors[ancestor_level]);
}

static __always_inline struct scw_group *scw_group_of(u64 cgid)
{
	return bpf_map_lookup_elem(&scw_groups, &cgid);
}

/* Nearest ancestor of @cgrp that already has a group context. */
static __always_inline u64 scw_parent_cgid(struct cgroup *cgrp)
{
	int i, level = BPF_CORE_READ(cgrp, level);

	if (level > SCX_CGROUP_WEIGHT_MAX_DEPTH)
		level = SCX_CGROUP_WEIGHT_MAX_DEPTH;

	bpf_for(i, 1, level + 1)
	{
		struct cgroup	 *anc;
		struct scw_group *g;
		u64		  cgid;

		anc = scw_cgroup_ancestor(cgrp, level - i);
		if (!anc)
			continue;
		cgid = scw_cgroup_id(anc);
		g    = scw_group_of(cgid);
		if (g && g->present)
			return cgid;
	}

	return 0;
}

__hidden int scx_cgroup_weight_lib_init(struct scx_cgroup_weight_config *config)
{
	if (!config)
		return -EINVAL;

	return 0;
}

__hidden int
scx_cgroup_weight_init(struct cgroup *cgrp		 __arg_trusted,
		       struct scx_cgroup_init_args *args __arg_trusted)
{
	struct scw_group group = {
		.weight	   = 100,
		.parent_id = 0,
		.level	   = 0,
		.idle	   = 0,
		.present   = 1,
	};
	u64 cgid;

	if (!cgrp || !args)
		return -EINVAL;

	/*
	 * The root cgroup has no group of its own: fair.c weighs a task at
	 * the root by its nice weight, with no shares/load scaling.
	 */
	if (!BPF_CORE_READ(cgrp, level))
		return 0;

	cgid = scw_cgroup_id(cgrp);
	if (!cgid)
		return -EINVAL;

	group.weight = args->weight ? args->weight : 100;
	group.idle   = bpf_core_field_exists(args->sched_idle) &&
		       args->sched_idle;
	group.level  = BPF_CORE_READ(cgrp, level);
	if (group.idle)
		SCW_STAT_INC(init_idle);
	group.parent_id = group.level ? scw_parent_cgid(cgrp) : 0;

	if (bpf_map_update_elem(&scw_groups, &cgid, &group, BPF_ANY))
		return -ENOMEM;

	scw_epoch_bump();
	return 0;
}

__hidden void scx_cgroup_weight_exit(struct cgroup *cgrp __arg_trusted)
{
	struct scw_group *g;
	u64		  cgid;

	if (!cgrp)
		return;
	cgid = scw_cgroup_id(cgrp);
	if (!cgid)
		return;

	g = scw_group_of(cgid);
	if (!g)
		return;

	/*
	 * Do not delete the entry: another CPU may hold the map value. A
	 * cgroup with live tasks cannot be destroyed, so its loads are zero
	 * by the time this runs.
	 */
	WRITE_ONCE(g->present, 0);
	WRITE_ONCE(g->weight, 1);
	WRITE_ONCE(g->idle, 0);
	scw_epoch_bump();
}

__hidden void scx_cgroup_weight_set_weight(struct cgroup *cgrp __arg_trusted,
					   u32		       weight)
{
	struct scw_group *g;
	struct scw_group  fresh = {
		.weight	 = 100,
		.level	 = 0,
		.present = 1,
	};
	u64 cgid;

	if (!cgrp)
		return;
	if (!BPF_CORE_READ(cgrp, level))
		return;
	cgid = scw_cgroup_id(cgrp);
	if (!cgid)
		return;

	g = scw_group_of(cgid);
	if (g) {
		WRITE_ONCE(g->weight, weight ? weight : 100);
		scw_epoch_bump();
		return;
	}

	fresh.weight	= weight ? weight : 100;
	fresh.level	= BPF_CORE_READ(cgrp, level);
	fresh.parent_id = fresh.level ? scw_parent_cgid(cgrp) : 0;
	bpf_map_update_elem(&scw_groups, &cgid, &fresh, BPF_ANY);
	scw_epoch_bump();
}

__hidden void scx_cgroup_weight_set_idle(struct cgroup *cgrp __arg_trusted,
					 bool		     idle)
{
	struct scw_group *g;
	struct scw_group  fresh = {
		.weight	 = 100,
		.level	 = 0,
		.present = 1,
	};
	u64 cgid;

	if (!cgrp)
		return;
	if (!BPF_CORE_READ(cgrp, level))
		return;
	cgid = scw_cgroup_id(cgrp);
	if (!cgid)
		return;

	if (idle)
		SCW_STAT_INC(idle_on);
	else
		SCW_STAT_INC(idle_off);

	g = scw_group_of(cgid);
	if (g) {
		WRITE_ONCE(g->idle, idle ? 1 : 0);
		scw_epoch_bump();
		return;
	}

	fresh.idle	= idle ? 1 : 0;
	fresh.level	= BPF_CORE_READ(cgrp, level);
	fresh.parent_id = fresh.level ? scw_parent_cgid(cgrp) : 0;
	bpf_map_update_elem(&scw_groups, &cgid, &fresh, BPF_ANY);
	scw_epoch_bump();
}

__hidden int scx_cgroup_weight_node(struct cgroup *cgrp __arg_trusted, s32 cpu,
				    struct scx_cgroup_weight_node *out)
{
	struct scw_group *g;

	if (!cgrp || !out || cpu < 0)
		return -EINVAL;

	/*
	 * Read the epoch before the entry. A concurrent cpu.weight or
	 * cpu.idle change stores the value first and bumps the epoch after
	 * it, so a value read here is never paired with an older epoch than
	 * the one the caller already holds.
	 */
	out->epoch     = scx_cgroup_weight_epoch();
	out->cgrp_id   = scw_cgroup_id(cgrp);
	out->parent_id = 0;
	out->weight    = 0;
	out->idle      = 0;
	out->present   = 0;
	out->pad       = 0;

	if (!out->cgrp_id)
		return 0;

	g = scw_group_of(out->cgrp_id);
	if (!g || !READ_ONCE(g->present))
		return 0;

	out->parent_id = READ_ONCE(g->parent_id);
	out->weight    = READ_ONCE(g->weight);
	out->idle      = READ_ONCE(g->idle);
	out->present   = 1;
	return 0;
}
