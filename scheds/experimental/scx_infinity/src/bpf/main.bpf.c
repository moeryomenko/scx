/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_infinity core policy.
 *
 * One vtime-ordered DSQ per CPU holds the runnable tasks. The key is a
 * scheduler-owned sequence, not wall time: a head insert takes the next
 * key below INF_KEY_MID and a tail insert the next key above it. The
 * kernel pops the lowest key first, so the most recent head insert runs
 * first and a tail insert runs last. That is the bounded-LIFO order of
 * the Infinity fair policy.
 *
 * Regular enqueues pass a 7:1 gate. Every eighth regular enqueue takes a
 * tail key and the other seven take a head key, so at most seven normal
 * arrivals can move ahead of a queued task between two tail insertions.
 * A fresh wakeup is exempt and enters at the head. An expired slice, a
 * requeue or a forced-progress enqueue enters at the tail, and a yield
 * zeroes the slice so the core hands the task back through the same
 * tail path.
 *
 * The slice is proportional to the task's effective weight over the
 * contending weight on the target CPU. The effective weight folds the
 * cgroup hierarchy in through the shared cgroup control library: nested
 * cpu.weight, cpu.idle and cpu.max are all enforced by
 * lib/cgroup_ctl.bpf.c, which wraps lib/cgroup_bw.bpf.c and
 * lib/cgroup_weight.bpf.c.
 *
 * The task context lives in the BPF arena because the bandwidth library
 * parks throttled tasks on an arena queue with the task context embedded in
 * it.
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/cgroup_ctl.h>
#include <lib/sdt_task.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Possible CPU count comes from the shared lib/bitmap.bpf.c definition; the
 * loader publishes it through the rodata `nr_cpu_ids` field before load.
 */
extern const volatile u32 nr_cpu_ids;

/*
 * Whether cpu.max is enforced. The loader clears it with --no-cpu-max or
 * when the running kernel has no support. cpu.weight and cpu.idle are
 * always on.
 */
const volatile bool enable_cpu_bw = true;

/*
 * Live configuration. The loader replaces the single entry with one map
 * update, so every reader sees either the old or the new value.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_cfg);
} cfg_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_MAX_CPUS);
	__type(key, u32);
	__type(value, struct inf_cpu_ctx);
} cpu_ctx_stor SEC(".maps");

/*
 * Scheduler-local topology. The loader fills one row per CPU and one
 * distance row per node before load. Keeping the data here leaves the
 * placement policy out of the shared utilities.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_MAX_CPUS);
	__type(key, u32);
	__type(value, struct inf_cpu_topo);
} topo_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_MAX_NODES);
	__type(key, u32);
	__type(value, struct inf_node_topo);
} node_topo_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_stats);
} stats_stor SEC(".maps");

/*
 * Per-task context, allocated in the arena by scx_task_alloc(). The
 * bandwidth context must stay first: REGISTER_SCX_CGROUP_BW_ENQUEUE_CB()
 * and the scx_cgroup_bw_* API cast the context to scx_task_common at offset
 * 0.
 */
struct task_ctx {
	struct scx_task_cgroup_bw cg_bw; /* MUST be first */
	u64 base_weight; /* p->scx.weight at the last change */
	u64 weight; /* effective weight, hierarchy folded in */
	u64 group_scale; /* folded shares/load product, Q10 */
	u64 slice_ns; /* last assigned quantum */
	u64 last_running_ns; /* clock at the last ops.running() */
	s32 queued_cpu; /* DSQ CPU, -1 when not queued */
	s32 group_cpu; /* CPU the group load is charged to */
	u32 joined; /* 1 while the cgroup load counts this task */
	u32 yielded;
	u32 wake_fork;
	u32 idle;
	u32 pid;
	u32 pad;
};

typedef struct task_ctx __arena task_ctx;

/* intf.h carries the same layout for the loader's arena sizing. */
_Static_assert(sizeof(struct task_ctx) == sizeof(struct inf_task_ctx_layout),
	       "task_ctx layout mirror in intf.h is out of sync");

static task_ctx *inf_task_ctx(struct task_struct *p)
{
	return (task_ctx *)__scx_task_data(p);
}

static task_ctx *inf_task_ctx_alloc(struct task_struct *p)
{
	return (task_ctx *)scx_task_alloc(p);
}

static struct inf_cpu_ctx *inf_cpu_ctx(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= INF_MAX_CPUS)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&cpu_ctx_stor, &key);
}

static struct inf_stats *inf_stats(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&stats_stor, &key);
}

static __always_inline bool inf_cpu_bw_enabled(void)
{
	return enable_cpu_bw;
}

/*
 * One lookup per decision. The entry is never resized, so the returned
 * pointer stays valid for the rest of the hook. The compiled-in defaults
 * cover the window before the loader publishes the first value.
 */
static __always_inline struct inf_cfg *inf_cfg(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&cfg_stor, &key);
}

static __always_inline u64 inf_cfg_quantum_ns(void)
{
	struct inf_cfg *cfg = inf_cfg();

	return cfg ? READ_ONCE(cfg->quantum_ns) : INF_QUANTUM_DEFAULT_NS;
}

/*
 * Weighted quantum:
 *
 *     q = max(quantum_ns * w / W, 1)
 *
 * W includes the task itself. A zero weight is the lightest task and a
 * zero normalizer falls back to one task. Weights cap at INF_WEIGHT_CAP,
 * so the product stays inside 64 bits on the BPF target.
 */
static __always_inline u64 inf_quantum(u64 w, u64 total)
{
	u64 base = inf_cfg_quantum_ns();
	u64 q;

	if (w == 0)
		w = 1;
	if (w > INF_WEIGHT_CAP)
		w = INF_WEIGHT_CAP;
	if (total < w)
		total = w;
	if (base == 0)
		return 1;
	q = base * w / total;
	return q ? q : 1;
}

/*
 * Effective weight of @p on @cpu through the shared cgroup library. The
 * library folds every cpu.weight level, honours cpu.idle and reports the
 * fixed-point group scale for later reweights.
 */
static __always_inline u64 inf_effective_weight(struct task_struct *p, s32 cpu,
						bool joining, task_ctx *tctx)
{
	struct scx_cgroup_weight_info info = {};
	u64			      w;

	scx_cgroup_ctl_weight(p, cpu, joining, &info);
	w = info.weight ? info.weight : 1;

	if (tctx) {
		tctx->group_scale = info.scale;
		tctx->idle	  = info.idle;
	}
	return w;
}

/* Reweight a task from its new base weight and stored group scale. */
static __always_inline u64 inf_reweight(u64 base, u64 scale, u32 idle)
{
	if (idle)
		return SCX_CGROUP_WEIGHT_IDLE;
	if (base == 0)
		base = 1;
	if (scale == 0)
		scale = SCX_CGROUP_WEIGHT_ONE;

	base = (base * scale + (SCX_CGROUP_WEIGHT_ONE / 2)) >>
	       SCX_CGROUP_WEIGHT_SHIFT;
	return base ? base : 1;
}

static __always_inline u64 inf_task_weight(struct task_struct *p)
{
	task_ctx *tctx = inf_task_ctx(p);

	if (tctx && tctx->weight)
		return tctx->weight;
	if (p->scx.weight)
		return p->scx.weight;
	return 1;
}

/*
 * Take the next key. Head keys move down from INF_KEY_MID and tail keys
 * up from it. A head key is therefore always ordered before every tail
 * key, and newer head keys are ordered before older ones.
 */
static __always_inline u64 inf_head_key(struct inf_cpu_ctx *cctx)
{
	return __sync_fetch_and_add(&cctx->head_seq, (u64)-1) - 1;
}

static __always_inline u64 inf_tail_key(struct inf_cpu_ctx *cctx)
{
	return __sync_fetch_and_add(&cctx->tail_seq, 1);
}

static __always_inline u32 inf_nr_cpu_ids(void)
{
	u32 n = nr_cpu_ids;

	if (!n)
		n = scx_bpf_nr_cpu_ids();
	return n;
}

/*
 * Preempt only a fresh wakeup that took a head slot. The newcomer must be
 * heavier than the running task and the victim must retain at least the
 * configured preemption margin, so a task that is about to expire
 * finishes instead of taking an IPI. A task under a cpu.idle cgroup never
 * preempts.
 */
static __always_inline void inf_maybe_preempt(struct task_struct *p, s32 cpu,
					      u64 enq_flags, bool head, u64 w)
{
	task_ctx	   *tctx;
	struct task_struct *victim;
	struct inf_stats   *stats;
	u64		    reserve;
	u64		    victim_w;

	if (!head || !(enq_flags & SCX_ENQ_WAKEUP))
		return;
	if (p->policy != INF_SCHED_NORMAL && p->policy != INF_SCHED_EXT)
		return;

	tctx = inf_task_ctx(p);
	if (tctx && tctx->wake_fork) {
		tctx->wake_fork = 0;
		return;
	}
	if (tctx && tctx->idle)
		return;

	victim = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!victim || victim == p)
		return;
	if (!(victim->scx.flags & SCX_TASK_QUEUED))
		return;

	victim_w = inf_task_weight(victim);
	if (w <= victim_w)
		return;

	{
		struct inf_cfg *cfg = inf_cfg();

		reserve = cfg ? READ_ONCE(cfg->preempt_margin_ns) : 0;
	}
	if (READ_ONCE(victim->scx.slice) < reserve)
		return;

	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	stats = inf_stats();
	if (stats)
		__sync_fetch_and_add(&stats->preemptions, 1);
}

/* Scheduler-local topology row for a CPU, or NULL out of range. */
static __always_inline struct inf_cpu_topo *inf_cpu_topo(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= INF_MAX_CPUS)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&topo_stor, &key);
}

/* An allowed CPU is online and present in the task's affinity mask. */
static __always_inline bool inf_cpu_allowed(struct task_struct	*p,
					    struct inf_cpu_topo *t, s32 cpu)
{
	if (!t || !t->online)
		return false;
	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

static __always_inline s32 inf_first_allowed(struct task_struct *p,
					     bool		 primary_only)
{
	u32 ncpu = inf_nr_cpu_ids();
	s32 cpu;

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		struct inf_cpu_topo *t;

		if ((u32)cpu >= ncpu)
			break;
		t = inf_cpu_topo(cpu);
		if (!inf_cpu_allowed(p, t, cpu))
			continue;
		if (primary_only && !t->core_primary)
			continue;
		return cpu;
	}
	return -1;
}

/* Advisory queue depth. A stale value only changes the chosen CPU. */
static __always_inline u32 inf_cpu_depth(s32 cpu)
{
	struct inf_cpu_ctx *cctx = inf_cpu_ctx(cpu);
	s64		    depth;

	if (!cctx)
		return 0;
	depth = READ_ONCE(cctx->depth);
	if (depth <= 0)
		return 0;
	if (depth > 0xffffffffU)
		return 0xffffffffU;
	return (u32)depth;
}

struct inf_pick_score {
	s32 cpu;
	u32 cls;
	u32 distance;
	u32 capacity;
	u32 depth;
};

/* Idle candidates: lower class, then nearer node, then faster CPU. */
static __noinline bool inf_score_better(const struct inf_pick_score *a,
					const struct inf_pick_score *b)
{
	if (a->cls != b->cls)
		return a->cls < b->cls;
	if (a->distance != b->distance)
		return a->distance < b->distance;
	if (a->capacity != b->capacity)
		return a->capacity > b->capacity;
	if (a->depth != b->depth)
		return a->depth < b->depth;
	return a->cpu < b->cpu;
}

/* Capacity fallback: a CPU below the spill threshold wins first. */
static __noinline bool inf_capacity_better(const struct inf_pick_score *a,
					   const struct inf_pick_score *b,
					   u32				spill)
{
	bool a_fits = a->depth < spill;
	bool b_fits = b->depth < spill;

	if (a_fits != b_fits)
		return a_fits;
	if (a->capacity != b->capacity)
		return a->capacity > b->capacity;
	if (a->depth != b->depth)
		return a->depth < b->depth;
	return a->cpu < b->cpu;
}

/*
 * Locality-first CPU selection.
 *
 * The scan assigns each allowed, online CPU one placement class and keeps
 * the best class, so one pass covers every step of the order:
 *
 *   0  fully idle physical core in the local LLC
 *   1  fully idle physical core in the local NUMA node
 *   2  fully idle physical core in another NUMA node
 *   3  idle SMT thread in the local LLC
 *   4  idle SMT thread in the local NUMA node
 *   5  idle SMT thread in another NUMA node
 *   6  capacity and depth ranking, with no idle CPU free
 *
 * The previous CPU is taken earlier when it is idle, and the idleness
 * test also claims the CPU. A lost claim falls back to the kernel's idle
 * picker. Affinity and cpuset limits come from p->cpus_ptr, and an
 * offline CPU has online == 0 in the seeded topology.
 */
s32 BPF_STRUCT_OPS(infinity_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	const struct cpumask *idle_mask, *core_mask;
	struct inf_cpu_topo  *lt;
	struct inf_cfg	     *cfg;
	struct inf_node_topo *node_row = NULL;
	struct inf_pick_score best     = { .cpu = -1 };
	struct inf_pick_score cap      = { .cpu = -1 };
	task_ctx	     *tctx;
	u32		      ncpu, mode, spill;
	u32		      local_node = 0, local_llc = 0;
	u32		      nkey;
	s32		      cpu, local_cpu, this_cpu;
	bool		      use_smt;

	/* Sample the live placement preferences once for this decision. */
	cfg	= inf_cfg();
	use_smt = !cfg || cfg->smt_enabled;
	mode	= cfg ? cfg->placement_mode : INF_PLACEMENT_AUTO;
	spill	= cfg && cfg->spill_threshold ? cfg->spill_threshold : 1;

	/* Remember the fork wakeup for the preemption check. */
	tctx = inf_task_ctx(p);
	if (tctx)
		tctx->wake_fork = !!(wake_flags & SCX_WAKE_FORK);

	/* A pinned task has no choice beyond its mask. */
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
		struct inf_cpu_topo *t = inf_cpu_topo(prev_cpu);

		if (inf_cpu_allowed(p, t, prev_cpu))
			return prev_cpu;
		cpu = inf_first_allowed(p, !use_smt);
		if (cpu >= 0)
			return cpu;
		return inf_first_allowed(p, false);
	}

	/* Previous CPU when it is idle, allowed, and not an SMT sibling. */
	lt = inf_cpu_topo(prev_cpu);
	if (inf_cpu_allowed(p, lt, prev_cpu) && (use_smt || lt->core_primary) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	/* Locality anchor: the waker CPU when allowed, else the previous. */
	this_cpu  = bpf_get_smp_processor_id();
	local_cpu = -1;
	lt	  = inf_cpu_topo(this_cpu);
	if (inf_cpu_allowed(p, lt, this_cpu)) {
		local_cpu = this_cpu;
	} else {
		lt = inf_cpu_topo(prev_cpu);
		if (inf_cpu_allowed(p, lt, prev_cpu))
			local_cpu = prev_cpu;
	}
	if (local_cpu < 0)
		local_cpu = inf_first_allowed(p, !use_smt);
	if (local_cpu < 0)
		return -1;

	lt = inf_cpu_topo(local_cpu);
	if (lt) {
		local_node = lt->node_id;
		local_llc  = lt->llc_id;
	}

	if (local_node < INF_MAX_NODES) {
		nkey	 = local_node;
		node_row = bpf_map_lookup_elem(&node_topo_stor, &nkey);
	}

	ncpu	  = inf_nr_cpu_ids();

	idle_mask = scx_bpf_get_idle_cpumask();
	core_mask = scx_bpf_get_idle_smtmask();

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		struct inf_pick_score s;
		struct inf_cpu_topo  *t;
		bool		      core_idle, thread_idle;
		u32		      cls, distance = 0;

		if ((u32)cpu >= ncpu)
			break;
		t = inf_cpu_topo(cpu);
		if (!inf_cpu_allowed(p, t, cpu))
			continue;
		if (!use_smt && !t->core_primary)
			continue;

		core_idle   = bpf_cpumask_test_cpu(cpu, core_mask);
		thread_idle = bpf_cpumask_test_cpu(cpu, idle_mask);

		if (mode == INF_PLACEMENT_MACHINE) {
			cls = INF_CLASS_CAPACITY;
		} else {
			/*
			 * A bounded mode never leaves its domain, for an
			 * idle CPU or for the capacity fallback.
			 */
			if (mode == INF_PLACEMENT_LLC && t->llc_id != local_llc)
				continue;
			if (mode == INF_PLACEMENT_NUMA &&
			    t->node_id != local_node)
				continue;

			if (core_idle) {
				if (t->llc_id == local_llc)
					cls = INF_CLASS_IDLE_CORE_LLC;
				else if (t->node_id == local_node)
					cls = INF_CLASS_IDLE_CORE_NODE;
				else
					cls = INF_CLASS_IDLE_CORE_REMOTE;
			} else if (thread_idle) {
				if (t->llc_id == local_llc)
					cls = INF_CLASS_IDLE_THREAD_LLC;
				else if (t->node_id == local_node)
					cls = INF_CLASS_IDLE_THREAD_NODE;
				else
					cls = INF_CLASS_IDLE_THREAD_REMOTE;
			} else {
				cls = INF_CLASS_CAPACITY;
			}
		}

		if (cls == INF_CLASS_IDLE_CORE_REMOTE ||
		    cls == INF_CLASS_IDLE_THREAD_REMOTE) {
			if (node_row && t->node_id < INF_MAX_NODES)
				distance = node_row->distance[t->node_id];
			else
				distance = INF_NODE_DISTANCE_FAR;
		}

		s.cpu	   = cpu;
		s.cls	   = cls;
		s.distance = distance;
		s.capacity = t->capacity;
		s.depth	   = inf_cpu_depth(cpu);

		if (cls == INF_CLASS_CAPACITY) {
			if (cap.cpu < 0 || inf_capacity_better(&s, &cap, spill))
				cap = s;
		} else {
			if (best.cpu < 0 || inf_score_better(&s, &best))
				best = s;
		}
	}

	scx_bpf_put_cpumask(core_mask);
	scx_bpf_put_cpumask(idle_mask);

	if (best.cpu >= 0) {
		if (scx_bpf_test_and_clear_cpu_idle(best.cpu))
			return best.cpu;

		/*
		 * Another CPU claimed the idle bit after the scan. In the
		 * unbounded modes ask the kernel for another idle CPU. A
		 * bounded mode keeps the scanned CPU, because the helper
		 * ignores the LLC and node bounds, and this CPU is still
		 * allowed even if it is no longer idle.
		 */
		if (mode == INF_PLACEMENT_AUTO ||
		    mode == INF_PLACEMENT_MACHINE) {
			cpu = scx_bpf_pick_idle_cpu(
				p->cpus_ptr, use_smt ? 0 : SCX_PICK_IDLE_CORE);
			if (cpu >= 0)
				return cpu;
		}
		return best.cpu;
	}

	if (cap.cpu >= 0)
		return cap.cpu;

	cpu = inf_first_allowed(p, !use_smt);
	if (cpu >= 0)
		return cpu;
	return local_cpu;
}

/*
 * Shared enqueue path. @reenq marks a call from the bandwidth callback: the
 * cgroup has just become unthrottled, so the throttle check is skipped.
 */
static int inf_enqueue_common(struct task_struct *p, u64 enq_flags, bool reenq)
{
	struct inf_cpu_ctx *cctx;
	task_ctx	   *tctx;
	struct inf_stats   *stats;
	u64		    key;
	u64		    q;
	u64		    w;
	u64		    base;
	u32		    seq;
	bool		    head = false;
	bool		    wake = !!(enq_flags & SCX_ENQ_WAKEUP);
	bool		    exempt;
	bool		    expired;
	bool		    newly_joined = false;
	s32		    cpu;
	int		    ret;

	if (!p)
		return -EINVAL;

	cpu = scx_bpf_task_cpu(p);
	if (cpu < 0 || (u32)cpu >= inf_nr_cpu_ids())
		cpu = bpf_get_smp_processor_id();
	if (cpu < 0 || (u32)cpu >= inf_nr_cpu_ids())
		return -EINVAL;

	cctx = inf_cpu_ctx(cpu);
	tctx = inf_task_ctx(p);
	if (!cctx || !tctx)
		return -EINVAL;

	stats = inf_stats();
	base  = tctx->base_weight ? tctx->base_weight :
				    (p->scx.weight ? p->scx.weight : 1);

	/*
	 * A task in a throttled cgroup is parked in the bandwidth backlog and
	 * is not on any of our queues. Its weight contribution is dropped
	 * until the callback re-enqueues it.
	 */
	if (inf_cpu_bw_enabled() && !reenq) {
		ret = scx_cgroup_ctl_throttled(p, (u64)tctx);
		if (ret == -EAGAIN) {
			if (tctx->joined) {
				scx_cgroup_ctl_leave(p, tctx->group_cpu,
						     tctx->base_weight);
				tctx->joined = 0;
			}
			if (!scx_cgroup_ctl_put_aside(p, (u64)tctx, 0)) {
				if (stats)
					__sync_fetch_and_add(
						&stats->cgrp_throttled, 1);
				return 0;
			}
			/*
			 * A failed put-aside must not lose the task: fall
			 * through and enqueue it normally.
			 */
		}
	}

	expired = !READ_ONCE(p->scx.slice) && !wake &&
		  !(enq_flags & SCX_ENQ_HEAD);
	if (expired && !tctx->yielded && stats)
		__sync_fetch_and_add(&stats->expiries, 1);

	/*
	 * Head-exempt: core head hint, fresh wakeup.
	 * Tail: expiry, yield hand-back, requeue, forced progress.
	 * Otherwise the 7:1 gate decides.
	 */
	if (enq_flags & SCX_ENQ_HEAD) {
		head = true;
	} else if (expired || (enq_flags & (SCX_ENQ_REENQ | SCX_ENQ_LAST |
					    SCX_ENQ_PREEMPT))) {
		head = false;
	} else if (wake) {
		head = true;
	} else {
		seq  = __sync_fetch_and_add(&cctx->seq, 1);
		head = !(seq == (u32)-1 ||
			 (seq & INF_GATE_MASK) == INF_GATE_MASK);
	}
	tctx->yielded = 0;

	exempt = wake || expired ||
		 (enq_flags & (SCX_ENQ_HEAD | SCX_ENQ_REENQ | SCX_ENQ_LAST |
			       SCX_ENQ_PREEMPT));

	/*
	 * The task's cgroup load counts it from the first enqueue until the
	 * matching dequeue, so a rotation through expiry does not join twice.
	 */
	if (!tctx->joined) {
		w	     = inf_effective_weight(p, cpu, true, tctx);
		tctx->weight = w;
		scx_cgroup_ctl_join(p, cpu, base);
		tctx->joined	= 1;
		tctx->group_cpu = cpu;
		newly_joined	= true;
		if (stats) {
			stats->cgrp_eff_weight = w;
			stats->cgrp_scale      = tctx->group_scale;
		}
	} else {
		w = tctx->weight ? tctx->weight : base;
	}

	q   = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
	key = head ? inf_head_key(cctx) : inf_tail_key(cctx);

	/* Charge the queue before the insert so the pop sees this weight. */
	__sync_fetch_and_add(&cctx->w_sum, (s64)w);
	if (!scx_bpf_dsq_insert_vtime(p, (u64)cpu, q, key, 0)) {
		__sync_fetch_and_add(&cctx->w_sum, -(s64)w);
		if (newly_joined) {
			scx_cgroup_ctl_leave(p, cpu, base);
			tctx->joined = 0;
		}
		return -EINVAL;
	}
	__sync_fetch_and_add(&cctx->depth, 1);

	tctx->queued_cpu = cpu;
	tctx->slice_ns	 = q;

	if (stats) {
		if (exempt)
			__sync_fetch_and_add(&stats->exempt_inserts, 1);
		else if (head)
			__sync_fetch_and_add(&stats->head_inserts, 1);
		else
			__sync_fetch_and_add(&stats->tail_inserts, 1);
	}

	if (wake)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	else if (cpu != bpf_get_smp_processor_id())
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	inf_maybe_preempt(p, cpu, enq_flags, head, w);
	return 0;
}

void BPF_STRUCT_OPS(infinity_enqueue, struct task_struct *p, u64 enq_flags)
{
	inf_enqueue_common(p, enq_flags, false);
}

/*
 * Bandwidth callback: a group that throttled @p has time again. Re-enqueue
 * through the normal path so the task re-enters through the 7:1 gate and
 * rejoins its cgroup load.
 */
int inf_bw_enqueue(struct task_struct *p __arg_trusted, u64 ctx)
{
	struct inf_stats *stats;

	if (!inf_cpu_bw_enabled())
		return 0;

	inf_enqueue_common(p, SCX_ENQ_REENQ, true);

	stats = inf_stats();
	if (stats)
		__sync_fetch_and_add(&stats->cgrp_reenqueued, 1);

	return 0;
}
REGISTER_SCX_CGROUP_BW_ENQUEUE_CB(inf_bw_enqueue);

/*
 * Pop the head of the CPU's own vtime DSQ, recompute its slice against
 * the weight still contending on this CPU, and move it to the local DSQ.
 */
void BPF_STRUCT_OPS(infinity_dispatch, s32 cpu, struct task_struct *prev)
{
	struct inf_cpu_ctx *cctx;
	task_ctx	   *tctx;
	struct task_struct *p;
	u64		    q;
	u64		    w;

	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	/* Re-enqueue backlogged tasks of cgroups that got time again. */
	if (inf_cpu_bw_enabled())
		scx_cgroup_ctl_reenqueue();

	p = __COMPAT_scx_bpf_dsq_peek((u64)cpu);
	if (p) {
		tctx = inf_task_ctx(p);
		w    = tctx && tctx->weight ? tctx->weight : inf_task_weight(p);
		q    = inf_quantum(w, READ_ONCE(cctx->w_sum));
		scx_bpf_task_set_slice(p, q);
		if (tctx) {
			tctx->queued_cpu = -1;
			tctx->slice_ns	 = q;
		}

		if (scx_bpf_dsq_move_to_local((u64)cpu, 0)) {
			__sync_fetch_and_add(&cctx->w_sum, -(s64)w);
			__sync_fetch_and_add(&cctx->depth, -1);
			return;
		}

		if (tctx)
			tctx->queued_cpu = cpu;
	}

	/*
	 * The queue is empty and the previous task is still runnable with
	 * no slice left. Renew it in place instead of waiting for a round
	 * trip through enqueue.
	 */
	if (prev && !READ_ONCE(prev->scx.slice)) {
		tctx = inf_task_ctx(prev);
		w = tctx && tctx->weight ? tctx->weight : inf_task_weight(prev);
		q = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
		scx_bpf_task_set_slice(prev, q);
	}
}

void BPF_STRUCT_OPS(infinity_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct inf_cpu_ctx *cctx;
	task_ctx	   *tctx;
	u64		    w;
	s32		    cpu;

	(void)deq_flags;

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	/* The task stops being runnable: drop its cgroup contribution. */
	if (tctx->joined) {
		scx_cgroup_ctl_leave(p, tctx->group_cpu, tctx->base_weight);
		tctx->joined = 0;
	}

	if (tctx->queued_cpu < 0)
		return;

	cpu		 = tctx->queued_cpu;
	tctx->queued_cpu = -1;

	cctx		 = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	w = tctx->weight ? tctx->weight : inf_task_weight(p);
	__sync_fetch_and_add(&cctx->w_sum, -(s64)w);
	__sync_fetch_and_add(&cctx->depth, -1);
}

void BPF_STRUCT_OPS(infinity_set_weight, struct task_struct *p, u32 weight)
{
	struct inf_cpu_ctx *cctx;
	task_ctx	   *tctx;
	u64		    old_base;
	u64		    new_base;
	u64		    old;
	u64		    new;
	s32		    cpu;

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	old_base = tctx->base_weight;
	new_base = weight ? weight : 1;
	old	 = tctx->weight;
	new	 = inf_reweight(new_base, tctx->group_scale, tctx->idle);
	tctx->base_weight = new_base;
	tctx->weight	  = new;
	tctx->slice_ns	  = inf_quantum(new, new);

	if (tctx->joined)
		scx_cgroup_ctl_reweight(p, tctx->group_cpu, old_base, new_base);

	cpu = tctx->queued_cpu;
	if (cpu < 0)
		return;
	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * The queued node keeps its vtime position, but its contending
	 * weight and its next slice must match the new share.
	 */
	__sync_fetch_and_add(&cctx->w_sum, (s64)new - (s64)old);
	{
		u64 total      = READ_ONCE(cctx->w_sum);

		tctx->slice_ns = inf_quantum(new, total > new ? total : new);
	}
}

bool BPF_STRUCT_OPS(infinity_yield, struct task_struct *from,
		    struct task_struct *to)
{
	struct inf_stats *stats;
	task_ctx	 *tctx;

	(void)to;

	if (!from)
		return false;

	/* Yield forfeits the remaining slice; the core re-enqueues. */
	scx_bpf_task_set_slice(from, 0);
	tctx = inf_task_ctx(from);
	if (tctx)
		tctx->yielded = 1;

	stats = inf_stats();
	if (stats)
		__sync_fetch_and_add(&stats->yields, 1);

	return false;
}

void BPF_STRUCT_OPS(infinity_running, struct task_struct *p)
{
	task_ctx *tctx = inf_task_ctx(p);

	if (tctx)
		tctx->last_running_ns = scx_bpf_now();
}

void BPF_STRUCT_OPS(infinity_stopping, struct task_struct *p, bool runnable)
{
	task_ctx *tctx = inf_task_ctx(p);
	u64	  now, delta;

	(void)runnable;

	if (!tctx)
		return;

	now		      = scx_bpf_now();
	delta		      = now - tctx->last_running_ns;
	tctx->last_running_ns = now;

	if (delta && inf_cpu_bw_enabled())
		scx_cgroup_ctl_consume(p, (u64)tctx, delta);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(infinity_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	task_ctx *tctx;
	int	  i;

	(void)args;

	tctx = inf_task_ctx_alloc(p);
	if (!tctx)
		return -ENOMEM;

	/* Zero the whole context, then seed the live fields. */
	bpf_for(i, 0, (int)sizeof(*tctx))
	{
		((char __arena *)tctx)[i] = 0;
	}

	tctx->base_weight     = p->scx.weight ? p->scx.weight : 1;
	tctx->weight	      = tctx->base_weight;
	tctx->group_scale     = SCX_CGROUP_WEIGHT_ONE;
	tctx->slice_ns	      = 0;
	tctx->last_running_ns = scx_bpf_now();
	tctx->queued_cpu      = -1;
	tctx->group_cpu	      = -1;
	tctx->joined	      = 0;
	tctx->yielded	      = 0;
	tctx->wake_fork	      = 0;
	tctx->idle	      = 0;
	tctx->pid	      = p->pid;
	return 0;
}

s32 BPF_STRUCT_OPS(infinity_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	task_ctx *tctx = inf_task_ctx(p);

	(void)args;

	if (tctx) {
		if (tctx->joined)
			scx_cgroup_ctl_leave(p, tctx->group_cpu,
					     tctx->base_weight);
		/*
		 * Mark the task dead in the bandwidth queues before freeing the
		 * context; concurrent drains holding the task must finish.
		 */
		if (inf_cpu_bw_enabled())
			scx_cgroup_ctl_cancel((u64)tctx,
					      SCX_CGROUP_BW_CANCEL_DROP);
	}

	scx_task_free_rcu(p);
	return 0;
}

s32 BPF_STRUCT_OPS(infinity_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	return scx_cgroup_ctl_cgroup_init(cgrp, args);
}

void BPF_STRUCT_OPS(infinity_cgroup_exit, struct cgroup *cgrp)
{
	scx_cgroup_ctl_cgroup_exit(cgrp);
}

void BPF_STRUCT_OPS(infinity_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	scx_cgroup_ctl_set_weight(cgrp, weight);
}

void BPF_STRUCT_OPS(infinity_cgroup_set_idle, struct cgroup *cgrp, bool idle)
{
	scx_cgroup_ctl_set_idle(cgrp, idle);
}

void BPF_STRUCT_OPS(infinity_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	int ret = scx_cgroup_ctl_set_bandwidth(cgrp, period_us, quota_us,
					       burst_us);

	if (ret)
		scx_bpf_error("Failed to set cgroup bandwidth: %d", ret);
}

void BPF_STRUCT_OPS(infinity_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct scx_cgroup_weight_info info = {};
	task_ctx		     *tctx;
	int			      ret;

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	ret = scx_cgroup_ctl_move(p, (u64)tctx, from, to, tctx->group_cpu,
				  tctx->base_weight, tctx->joined != 0);
	if (ret)
		scx_bpf_error("Failed to move a task between cgroups: %d", ret);

	/*
	 * The task is now accounted on the new path; refresh the folded
	 * weight for its next quantum.
	 */
	if (tctx->joined) {
		scx_cgroup_ctl_weight(p, tctx->group_cpu, false, &info);
		tctx->weight	  = info.weight ? info.weight : 1;
		tctx->group_scale = info.scale;
		tctx->idle	  = info.idle;
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(infinity_init)
{
	struct inf_cpu_ctx	    *cctx;
	struct scx_cgroup_ctl_config ctl = {
		.verbose   = 0,
		.enable_bw = enable_cpu_bw,
	};
	u32 ncpu = inf_nr_cpu_ids();
	u32 key;
	s32 cpu;
	int ret;

	if (ncpu > INF_MAX_CPUS)
		ncpu = INF_MAX_CPUS;

	/*
	 * Bring up cpu.weight and cpu.idle, and cpu.max when the loader kept
	 * it on. A kernel without cpu.max support leaves the weight half
	 * usable, so the scheduler still loads.
	 */
	ret = scx_cgroup_ctl_lib_init(&ctl);
	if (ret) {
		scx_bpf_error("failed to initialize cgroup control: %d", ret);
		return ret;
	}

	/*
	 * Array maps start zeroed. Seed both key runs before any CPU can
	 * enqueue, and create one DSQ per possible CPU.
	 */
	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		if (cpu < 0)
			continue;
		key  = (u32)cpu;
		cctx = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cctx) {
			cctx->head_seq = INF_KEY_MID;
			cctx->tail_seq = INF_KEY_MID;
			cctx->w_sum    = 0;
			cctx->depth    = 0;
			cctx->seq      = 0;
		}
	}

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		if (cpu < 0)
			continue;
		if ((u32)cpu >= ncpu)
			break;
		ret = scx_bpf_create_dsq((u64)cpu,
					 __COMPAT_scx_bpf_cpu_node(cpu));
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("failed to create DSQ for cpu %d: %d",
				      cpu, ret);
			return ret;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(infinity_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(infinity_ops, .select_cpu = (void *)infinity_select_cpu,
	       .enqueue		     = (void *)infinity_enqueue,
	       .dispatch	     = (void *)infinity_dispatch,
	       .dequeue		     = (void *)infinity_dequeue,
	       .running		     = (void *)infinity_running,
	       .stopping	     = (void *)infinity_stopping,
	       .set_weight	     = (void *)infinity_set_weight,
	       .yield		     = (void *)infinity_yield,
	       .cgroup_init	     = (void *)infinity_cgroup_init,
	       .cgroup_exit	     = (void *)infinity_cgroup_exit,
	       .cgroup_set_weight    = (void *)infinity_cgroup_set_weight,
	       .cgroup_set_idle	     = (void *)infinity_cgroup_set_idle,
	       .cgroup_set_bandwidth = (void *)infinity_cgroup_set_bandwidth,
	       .cgroup_move	     = (void *)infinity_cgroup_move,
	       .init_task	     = (void *)infinity_init_task,
	       .exit_task	     = (void *)infinity_exit_task,
	       .init = (void *)infinity_init, .exit = (void *)infinity_exit,
	       .flags	   = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .timeout_ms = 20000, .name = "infinity");
