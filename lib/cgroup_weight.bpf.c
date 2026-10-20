/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Hierarchical cpu.weight and cpu.idle accounting.
 *
 * The model is fair.c's with one runqueue per CPU, as scx_eevdf implements
 * it: a group's load on a CPU is the weight of its direct task members plus
 * the share of each non-empty child group. A task's effective weight is its
 * nice weight scaled by shares / load at every level, carried in fixed point
 * and rounded once.
 *
 * Tasks join on their first enqueue and leave on dequeue, so a running task
 * stays counted in its group's load. A move while queued transfers the
 * contribution between the two cgroup paths.
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

struct scw_cpu_key {
	u64 cgid;
	u32 cpu;
	u32 pad;
};

struct scw_cpu_load {
	u64 load; /* members plus non-empty child shares */
	u64 nr; /* tasks queued in the group or below it */
	u64 contrib; /* what this group adds to its parent's load */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct scw_group);
	__uint(max_entries, SCX_CGROUP_WEIGHT_NR_CGRP_MAX);
} scw_groups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct scw_cpu_key);
	__type(value, struct scw_cpu_load);
	__uint(max_entries, SCX_CGROUP_WEIGHT_NR_CPU_ENTRIES);
} scw_cpu_loads SEC(".maps");

/*
 * Per-CPU accounting counters. A shares or idle change bumps @epoch once,
 * and a task that folds after that sees a different value at its next
 * enqueue or dispatch. The counters make a lifecycle bug visible instead of
 * a silent ratio error.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scx_cgroup_weight_stats);
} scw_stats_stor SEC(".maps");

/* Global change counter. Only a fold compares this value. */
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

/*
 * The task's cgroup, read from the task as tg_cgrp() does. A NULL
 * sched_task_group (CGROUP_SCHED off) or cgroup is the root, reported as
 * NULL. The caller holds the task's rq lock, which pins the pointer.
 */
static __always_inline struct cgroup *scw_task_cgroup(struct task_struct *p)
{
	struct task_group *tg;

	if (!bpf_core_field_exists(struct task_struct, sched_task_group))
		return NULL;

	tg = BPF_CORE_READ(p, sched_task_group);
	if (!tg)
		return NULL;

	return BPF_CORE_READ(tg, css.cgroup);
}

static __always_inline struct scw_group *scw_group_of(u64 cgid)
{
	return bpf_map_lookup_elem(&scw_groups, &cgid);
}

static __always_inline struct scw_cpu_load *scw_cpu_get(u64 cgid, s32 cpu,
							bool create)
{
	struct scw_cpu_key key = {
		.cgid = cgid,
		.cpu  = (u32)cpu,
	};
	struct scw_cpu_load *load;

	load = bpf_map_lookup_elem(&scw_cpu_loads, &key);
	if (load || !create)
		return load;

	{
		struct scw_cpu_load zero = {};

		/*
		 * A lost race means the winner created the same entry; the
		 * second lookup returns it. The entries are not deleted, so a
		 * pointer once published stays valid.
		 */
		if (bpf_map_update_elem(&scw_cpu_loads, &key, &zero,
					BPF_NOEXIST))
			;
	}
	return bpf_map_lookup_elem(&scw_cpu_loads, &key);
}

/* Nearest present group at or above @cgrp. 0 when the task is under root. */
static __always_inline u64 scw_first_present(struct cgroup *cgrp)
{
	int i, level;

	if (!cgrp)
		return 0;

	level = BPF_CORE_READ(cgrp, level);
	if (level >= SCX_CGROUP_WEIGHT_MAX_DEPTH)
		level = SCX_CGROUP_WEIGHT_MAX_DEPTH - 1;

	bpf_for(i, 0, level + 1)
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

/*
 * Add @delta to the task count of every present group on @cgrp's path. The
 * counts decide whether a child contributes its share to its parent.
 */
static void scw_nr_add(struct cgroup *cgrp, s32 cpu, s64 delta)
{
	int i, level;

	if (!cgrp)
		return;

	level = BPF_CORE_READ(cgrp, level);
	if (level >= SCX_CGROUP_WEIGHT_MAX_DEPTH)
		level = SCX_CGROUP_WEIGHT_MAX_DEPTH - 1;

	bpf_for(i, 0, level + 1)
	{
		struct cgroup	    *anc;
		struct scw_group    *g;
		struct scw_cpu_load *load;
		u64		     cgid;

		anc = scw_cgroup_ancestor(cgrp, level - i);
		if (!anc)
			continue;
		cgid = scw_cgroup_id(anc);
		g    = scw_group_of(cgid);
		if (!g || !g->present)
			continue;
		load = scw_cpu_get(cgid, cpu, true);
		if (load) {
			if (delta < 0) {
				u64 prev =
					__sync_fetch_and_add(&load->nr, delta);

				if (prev < (u64)(-delta)) {
					WRITE_ONCE(load->nr, 0);
					SCW_STAT_INC(nr_underflows);
				}
			} else {
				__sync_fetch_and_add(&load->nr, delta);
			}
		}
	}
}
/*
 * Bring each group on the path from @cgid up in line with its task count:
 * a non-empty group contributes its share to its parent, an empty one
 * contributes nothing. A load move changes the group's own load, not its
 * contribution, so only the counts decide the target.
 */
static void scw_contrib_sync(u64 cgid, s32 cpu)
{
	u64 cur = cgid;
	int i;

	bpf_for(i, 0, SCX_CGROUP_WEIGHT_MAX_DEPTH)
	{
		struct scw_group    *g;
		struct scw_cpu_load *load, *parent;
		u64		     old, target;

		if (!cur)
			break;
		g = scw_group_of(cur);
		if (!g || !g->present)
			break;
		load = scw_cpu_get(cur, cpu, true);
		if (!load)
			break;

		target = READ_ONCE(load->nr) ? READ_ONCE(g->weight) : 0;
		old    = READ_ONCE(load->contrib);
		if (old != target &&
		    __sync_val_compare_and_swap(&load->contrib, old, target) ==
			    old) {
			if (g->parent_id) {
				parent = scw_cpu_get(g->parent_id, cpu, true);
				if (parent)
					__sync_fetch_and_add(&parent->load,
							     (s64)target -
								     (s64)old);
			}
		}

		cur = g->parent_id;
	}
}

/* Add @delta to @cgid's own load, then repair the contributions above it. */
static void scw_load_add(u64 cgid, s32 cpu, s64 delta)
{
	struct scw_cpu_load *load;

	load = scw_cpu_get(cgid, cpu, true);
	if (!load)
		return;

	if (delta < 0) {
		u64 prev = __sync_fetch_and_add(&load->load, delta);

		if (prev < (u64)(-delta)) {
			WRITE_ONCE(load->load, 0);
			SCW_STAT_INC(load_underflows);
		}
	} else {
		__sync_fetch_and_add(&load->load, delta);
	}
	scw_contrib_sync(cgid, cpu);
}

/*
 * Re-apply @cgid's new shares to every CPU where it has joined tasks. The
 * contribution is per (cgroup, CPU), so a shares change must move each
 * parent load it feeds, not just the CPU that happened to write the file.
 * The walk is bounded by the compile-time CPU ceiling; a shares write is
 * rare and the bound keeps the verifier path flat.
 */
static void scw_sync_group(u64 cgid)
{
	u32 cpu;

	bpf_for(cpu, 0, SCX_CGROUP_WEIGHT_MAX_CPUS)
	{
		struct scw_cpu_load *load;

		load = scw_cpu_get(cgid, (s32)cpu, false);
		if (load && READ_ONCE(load->nr))
			scw_contrib_sync(cgid, (s32)cpu);
	}
}

/*
 * Fold the hierarchy into the effective weight of @p on @cpu.
 *
 * @joining counts the task and the shares of the empty groups it joins, so
 * the result equals the loads after the matching scw_join_path(). With
 * @joining false the task is already in the loads and adds nothing, so a
 * refresh does not count it twice. A missing group (no cpu controller) is a
 * pass-through: its weight stays the base weight until the first group that
 * has a context.
 */
static int scw_fold(struct cgroup *cgrp, s32 cpu, u64 base, bool joining,
		    struct scx_cgroup_weight_info *out)
{
	u64 product = SCX_CGROUP_WEIGHT_ONE;
	u64 add	    = joining ? base : 0;
	u32 idle    = 0;
	int i, level;

	level = BPF_CORE_READ(cgrp, level);
	if (level >= SCX_CGROUP_WEIGHT_MAX_DEPTH)
		level = SCX_CGROUP_WEIGHT_MAX_DEPTH - 1;

	bpf_for(i, 0, level + 1)
	{
		struct cgroup	    *anc;
		struct scw_group    *g;
		struct scw_cpu_load *load;
		u64		     cgid, shares, total;

		anc = scw_cgroup_ancestor(cgrp, level - i);
		if (!anc)
			continue;
		cgid = scw_cgroup_id(anc);
		g    = scw_group_of(cgid);
		if (!g || !g->present)
			continue;

		if (READ_ONCE(g->idle))
			idle = 1;

		shares = READ_ONCE(g->weight);
		if (!shares)
			shares = 1;

		load  = scw_cpu_get(cgid, cpu, false);
		total = (load ? READ_ONCE(load->load) : 0) + add;
		/*
		 * An empty level must not scale the task. The shares are the
		 * denominator, as in src/policy.rs hierarchy_scale(), so a zero
		 * load gives a product of one. Using one as the denominator
		 * multiplied the weight by the shares and produced the live
		 * weights above one million seen in the revision 2 runs.
		 */
		if (!total)
			total = shares;

		/*
		 * A group whose load is below its share scales a member up.
		 * Cap the carried product so a deep chain of light groups
		 * cannot overflow the 64-bit multiplication.
		 */
		if (product > (1ULL << 20))
			product = 1ULL << 20;
		product = product * shares / total;
		add	= (joining && !(load && READ_ONCE(load->contrib))) ?
				  shares :
				  0;
	}

	out->scale  = product;
	out->idle   = idle;
	out->weight = (base * product + (SCX_CGROUP_WEIGHT_ONE / 2)) >>
		      SCX_CGROUP_WEIGHT_SHIFT;
	if (idle)
		out->weight = SCX_CGROUP_WEIGHT_IDLE;
	if (!out->weight)
		out->weight = 1;
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

	group.weight	= args->weight ? args->weight : 100;
	group.idle	= bpf_core_field_exists(args->sched_idle) &&
			  args->sched_idle;
	group.level	= BPF_CORE_READ(cgrp, level);
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
		scw_sync_group(cgid);
		scw_epoch_bump();
		return;
	}

	fresh.weight	= weight ? weight : 100;
	fresh.level	= BPF_CORE_READ(cgrp, level);
	fresh.parent_id = fresh.level ? scw_parent_cgid(cgrp) : 0;
	bpf_map_update_elem(&scw_groups, &cgid, &fresh, BPF_ANY);
	scw_sync_group(cgid);
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

__hidden int scx_cgroup_weight_task(struct task_struct *p __arg_trusted,
				    s32 cpu, bool joining,
				    struct scx_cgroup_weight_info *out)
{
	struct cgroup *cgrp;
	u64	       base;

	if (!p || !out)
		return -EINVAL;

	out->weight = 1;
	out->scale  = SCX_CGROUP_WEIGHT_ONE;
	out->idle   = 0;

	base	    = p->scx.weight;
	if (!base)
		base = 1;

	cgrp = scw_task_cgroup(p);
	if (!cgrp)
		return 0;

	return scw_fold(cgrp, cpu, base, joining, out);
}

__hidden int scx_cgroup_weight_fold(struct cgroup *cgrp __arg_trusted, s32 cpu,
				    u64 base_weight, bool joining,
				    struct scx_cgroup_weight_info *out)
{
	if (!cgrp || !out)
		return -EINVAL;

	if (!base_weight)
		base_weight = 1;

	return scw_fold(cgrp, cpu, base_weight, joining, out);
}

/*
 * Refold a task that is already counted in its group. @joining is false, so
 * the task does not add itself to the denominator a second time. The caller
 * compares the epoch first; this function only does the arithmetic.
 */
__hidden int scx_cgroup_weight_refresh(struct task_struct *p __arg_trusted,
				       s32 cpu, u64 base_weight,
				       struct scx_cgroup_weight_info *out)
{
	struct cgroup *cgrp;

	if (!p || !out)
		return -EINVAL;

	out->weight = 1;
	out->scale  = SCX_CGROUP_WEIGHT_ONE;
	out->idle   = 0;

	if (!base_weight)
		base_weight = 1;

	cgrp = scw_task_cgroup(p);
	if (!cgrp)
		return 0;

	SCW_STAT_INC(refolds);
	return scw_fold(cgrp, cpu, base_weight, false, out);
}

__hidden void scx_cgroup_weight_join(struct task_struct *p __arg_trusted,
				     s32 cpu, u64 base_weight)
{
	struct cgroup *cgrp;
	u64	       cgid;

	cgrp = scw_task_cgroup(p);
	if (!cgrp || !base_weight)
		return;

	cgid = scw_first_present(cgrp);
	if (!cgid)
		return;

	scw_nr_add(cgrp, cpu, 1);
	scw_load_add(cgid, cpu, (s64)base_weight);
	SCW_STAT_INC(joins);
	/*
	 * The join changed a level's load, so every fold that read it is
	 * stale. Without this a task that folded before a sibling group
	 * joined kept the pre-join scale for its whole runnable period.
	 */
	scw_epoch_bump();
}

__hidden void scx_cgroup_weight_leave(struct task_struct *p __arg_trusted,
				      s32 cpu, u64 base_weight)
{
	struct cgroup *cgrp;
	u64	       cgid;

	cgrp = scw_task_cgroup(p);
	if (!cgrp || !base_weight)
		return;

	cgid = scw_first_present(cgrp);
	if (!cgid)
		return;

	/* Drop the count first, so an emptying group sheds its share too. */
	scw_nr_add(cgrp, cpu, -1);
	scw_load_add(cgid, cpu, -(s64)base_weight);
	SCW_STAT_INC(leaves);
	scw_epoch_bump();
}

__hidden void scx_cgroup_weight_reweight(struct task_struct *p __arg_trusted,
					 s32 cpu, u64 old_weight,
					 u64 new_weight)
{
	struct cgroup *cgrp;
	u64	       cgid;

	if (old_weight == new_weight)
		return;

	cgrp = scw_task_cgroup(p);
	if (!cgrp)
		return;

	cgid = scw_first_present(cgrp);
	if (!cgid)
		return;

	scw_load_add(cgid, cpu, (s64)new_weight - (s64)old_weight);
	SCW_STAT_INC(reweights);
	scw_epoch_bump();
}

__hidden void scx_cgroup_weight_move(struct cgroup *from __arg_trusted,
				     struct cgroup *to __arg_trusted, s32 cpu,
				     u64 base_weight)
{
	u64 cgid;

	if (!base_weight)
		return;

	if (from) {
		cgid = scw_first_present(from);
		if (cgid) {
			scw_nr_add(from, cpu, -1);
			scw_load_add(cgid, cpu, -(s64)base_weight);
		}
	}

	if (to) {
		cgid = scw_first_present(to);
		if (cgid) {
			scw_nr_add(to, cpu, 1);
			scw_load_add(cgid, cpu, (s64)base_weight);
		}
	}

	SCW_STAT_INC(moves);
	scw_epoch_bump();
}
