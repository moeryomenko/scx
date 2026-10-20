/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_infinity core policy.
 *
 * One scheduler-owned queue per CPU holds the runnable tasks. The key is
 * a scheduler-owned sequence, not wall time: a head insert takes the next
 * key below INF_KEY_MID and a tail insert the next key above it. The
 * newest head insert is therefore first and a tail insert is last. That
 * is the bounded-LIFO order of the Infinity fair policy. The default
 * queue is scx_edq from lib/edq.h; the queue-list build feature swaps in
 * an intrusive FIFO list through the same interface.
 *
 * Regular enqueues pass a 7:1 gate. Every eighth regular enqueue takes a
 * tail key and the other seven take a head key, so at most seven normal
 * arrivals can move ahead of a queued task between two tail insertions.
 * SCX_ENQ_HEAD is the only head-exempt hint; sched_ext has no equivalent
 * of the kernel's curr == se exemption. A wakeup passes the gate like any
 * other enqueue. An expired slice, a requeue or a forced-progress enqueue
 * enters at the tail, and a yield zeroes the slice so the core hands the
 * task back through the same tail path.
 *
 * A sched_ext local DSQ is used only to run the task the scheduler
 * selected. Dispatch pops the local queue, then steals the head of a
 * same-LLC peer queue and then a same-NUMA peer queue.
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
 * it. The queue nodes are arena objects too, and one hold keeps a node
 * alive across the unlocked insert that follows a pop.
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/arena_map.h>
#include <lib/cgroup_ctl.h>
#include <lib/edq.h>
#include <lib/sdt_task.h>
#include "intf.h"
#include "queue.h"

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
 * 0. The ready-queue node follows it and is embedded for the task's whole
 * lifetime.
 */
struct task_ctx {
	struct scx_task_cgroup_bw cg_bw; /* MUST be first */
	INF_QUEUE_NODE_FIELD	  qnode; /* default EDQ node or list node */
	u64 base_weight; /* p->scx.weight at the last change */
	u64 weight; /* effective weight, hierarchy folded in */
	u64 group_scale; /* folded shares/load product, Q10 */
	u64 slice_ns; /* last assigned quantum */
	u64 last_running_ns; /* clock at the last ops.running() */
	u64 weight_epoch; /* cgroup epoch seen at the last fold */
	s32 queued_cpu; /* queue CPU, -1 when not queued */
	s32 group_cpu; /* CPU the group load is charged to */
	u32 state; /* enum inf_task_state */
	u32 moving; /* one writer owns a queue move */
	u32 reweight_pending; /* apply the new weight at the next step */
	u32 dequeue_pending; /* a dequeue arrived during a move */
	u32 exit_pending; /* an exit arrived during a move */
	u32 joined; /* 1 while the cgroup load counts this task */
	u32 yielded;
	u32 wake_fork;
	u32 idle;
	u32 pid;
	u32 hist_idx;
	struct inf_hist hist[8];
};

typedef struct task_ctx __arena task_ctx;

/*
 * The queue block is one arena allocation: one queue per possible CPU.
 * It is created in the sleepable ops.init() and never resized.
 */
static inf_queue_t *inf_queues;
static u32	    inf_nr_queues;

/*
 * Set from ops.disable(), which runs for every task while the scheduler is
 * being torn down. ops.exit_task() uses it to tell a task that died during
 * the run from one that is only being unregistered: a run-time exit drops
 * the task snapshot, a teardown keeps it for the exit dump.
 */
static bool inf_shutting_down;

#define TOUCH_ARENA()                           \
	do {                                    \
		asm volatile("" ::"r"(&arena)); \
	} while (0)

/* intf.h carries the same layout for the loader's arena sizing. */
_Static_assert(sizeof(struct task_ctx) == sizeof(struct inf_task_ctx_layout),
	       "task_ctx layout mirror in intf.h is out of sync");
_Static_assert(sizeof(struct inf_cgroup_weight_stats) ==
		       sizeof(struct scx_cgroup_weight_stats),
	       "cgroup weight counter mirror in intf.h is out of sync");
#ifdef INF_QUEUE_LIST
_Static_assert(sizeof(struct inf_list_node) <= INF_QUEUE_NODE_BYTES,
	       "queue-list node does not fit the shared layout");
#else
_Static_assert(sizeof(struct scx_edq_task) == INF_QUEUE_NODE_BYTES,
	       "EDQ node does not match INF_QUEUE_NODE_BYTES");
#endif

static __always_inline task_ctx *inf_task_ctx(struct task_struct *p)
{
	return (task_ctx *)__scx_task_data(p);
}

static __always_inline task_ctx *inf_task_ctx_alloc(struct task_struct *p)
{
	return (task_ctx *)scx_task_alloc(p);
}

/* Recover the task context from the queue node embedded in it. */
static __always_inline task_ctx *
inf_task_from_qnode(inf_queue_node_t __arg_arena *node)
{
	return (task_ctx *)(void __arena *)((u64)node -
					    offsetof(struct task_ctx, qnode));
}

/* One queue per CPU. The caller checks for NULL. */
static __always_inline inf_queue_t *inf_queue(s32 cpu)
{
	if (cpu < 0 || (u32)cpu >= inf_nr_queues)
		return NULL;
	return &inf_queues[cpu];
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

#define INF_STAT_INC(field)                                       \
	do {                                                      \
		struct inf_stats *__stats = inf_stats();          \
		if (__stats)                                      \
			__sync_fetch_and_add(&__stats->field, 1); \
	} while (0)

/*
 * Diagnostic trace, disabled unless the loader sets it before load. It is
 * a ring of queue transitions plus one task snapshot that keeps the last
 * transition of each live task, so a stall dump names the transition that
 * lost the task. The ABI lives in intf.h.
 */
const volatile bool enable_trace = false;

/* Controlled refusal of the local DSQ insert, for the fallback test. */
const volatile bool inject_dsq_refusal = false;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_trace_ctl);
} trace_ctl_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_TRACE_CAP);
	__type(key, u32);
	__type(value, struct inf_trace_rec);
} trace_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_MAX_CPUS);
	__type(key, u32);
	__type(value, struct inf_queue_snap);
} qsnap_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, INF_TASK_SNAP_MAX);
	__type(key, s32);
	__type(value, struct inf_task_snap);
} tsnap_stor SEC(".maps");

/*
 * Per-CPU scratch for the task snapshot. The value is too large for the
 * 512-byte BPF stack, so the tracer builds it in this map entry and then
 * publishes it with one hash update.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_task_snap);
} tsnap_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_test_ctl);
} test_stor SEC(".maps");

/*
 * Pack the source and destination CPU of a transition into one argument.
 * A BPF subprogram takes at most five arguments; -1 is a valid CPU value
 * here and survives the 16-bit round trip.
 */
#define INF_TR_WHERE(src, dst) \
	(((u64)(u32)(u16)(s32)(src)) | ((u64)(u32)(u16)(s32)(dst) << 16))

/*
 * The ring records only transitions that can lose a task or repair one.
 * A normal insert or pop is kept in the per-task snapshot instead, so a
 * ten-minute campaign does not overwrite the ring with steady-state
 * traffic. `total` counts every transition; `next` counts ringed ones.
 */
static __always_inline bool inf_trace_in_ring(u32 op)
{
	switch (op) {
	case INF_TR_ENQ_PARK:
	case INF_TR_ENQ_STALE:
	case INF_TR_ENQ_INSERT_FAIL:
	case INF_TR_DEQ_PENDING:
	case INF_TR_DEQ_REMOVE_FAIL:
	case INF_TR_POP_AFFINITY:
	case INF_TR_POP_PENDING:
	case INF_TR_DSQ_REFUSED:
	case INF_TR_REQUEUE_FAIL:
	case INF_TR_REMOVE_FAIL:
	case INF_TR_REWEIGHT:
		return true;
	default:
		return false;
	}
}

/*
 * The queue that actually owns the node, as a CPU index. The node link is
 * the source of truth for membership: queued_cpu can lag behind a move
 * that failed midway. Returns -1 when the node is unlinked or the owner
 * cannot be derived.
 */
static __noinline s32 inf_queue_owner_cpu(inf_queue_node_t *node)
{
	inf_queue_t __arg_arena *owner = inf_queue_node_owner(node);
	u64			 base, addr, span;

	if (!owner)
		return -1;
	base = (u64)inf_queues;
	addr = (u64)owner;
	span = (u64)inf_nr_queues * sizeof(*inf_queues);
	if (addr < base || addr >= base + span)
		return -1;
	if ((addr - base) % sizeof(*inf_queues))
		return -1;
	return (s32)((addr - base) / sizeof(*inf_queues));
}

static __noinline void inf_trace(u32 op, task_ctx *tctx, u64 where, s64 result)
{
	struct inf_trace_ctl *ctl;
	struct inf_trace_rec *rec;
	struct inf_task_snap *old, *snap;
	u64		      idx;
	u32		      key = 0;
	u32		      slot;
	s32		      pid;
	s32		      src = (s16)(u16)(where & 0xffff);
	s32		      dst = (s16)(u16)((where >> 16) & 0xffff);

	if (!enable_trace || !tctx)
		return;

	ctl = bpf_map_lookup_elem(&trace_ctl_stor, &key);
	if (!ctl)
		return;

	__sync_fetch_and_add(&ctl->total, 1);

	pid = (s32)tctx->pid;

	{
		u32 slot = tctx->hist_idx & 7;

		tctx->hist[slot].op	= op;
		tctx->hist[slot].src	= src;
		tctx->hist[slot].dst	= dst;
		tctx->hist[slot].result = (s32)result;
		tctx->hist[slot].state	= tctx->state;
		tctx->hist_idx++;
	}

	if (inf_trace_in_ring(op)) {
		idx  = __sync_fetch_and_add(&ctl->next, 1);
		slot = (u32)idx & (INF_TRACE_CAP - 1);
		rec  = bpf_map_lookup_elem(&trace_stor, &slot);
		if (rec) {
			rec->ts	       = bpf_ktime_get_ns();
			rec->seq       = idx;
			rec->slice     = tctx->slice_ns;
			rec->result    = result;
			rec->pid       = pid;
			rec->src_cpu   = src;
			rec->dst_cpu   = dst;
			rec->op	       = op;
			rec->state     = tctx->state;
			rec->hold      = inf_queue_node_hold(&tctx->qnode);
			rec->group_cpu = tctx->group_cpu;
		}
		if (idx >= INF_TRACE_CAP)
			__sync_fetch_and_add(&ctl->overwritten, 1);
	}

	if (pid <= 0)
		return;

	snap = bpf_map_lookup_elem(&tsnap_scratch, &key);
	if (!snap)
		return;
	old = bpf_map_lookup_elem(&tsnap_stor, &pid);
	if (!old)
		__builtin_memset(snap, 0, sizeof(*snap));
	else {
		/*
		 * Keep one previous transition per task. Two records tell a
		 * dispatch that failed after the pop from a task that was
		 * never popped at all.
		 */
		snap->prev_ts	  = old->ts;
		snap->prev_op	  = old->last_op;
		snap->prev_state  = old->state;
		snap->prev_src	  = old->last_src;
		snap->prev_dst	  = old->last_dst;
		snap->prev_result = old->last_result;
	}

	snap->hist_count = tctx->hist_idx > 8 ? 8 : tctx->hist_idx;
	{
		u32 i;

		bpf_for(i, 0, 8) {
			u32 slot = (tctx->hist_idx - snap->hist_count + i) & 7;

			snap->hist[i] = tctx->hist[slot];
		}
	}

	snap->ts		      = bpf_ktime_get_ns();
	snap->slice	      = tctx->slice_ns;
	snap->weight	      = tctx->weight;
	snap->pid	      = pid;
	snap->queued_cpu	      = tctx->queued_cpu;
	snap->group_cpu	      = tctx->group_cpu;
	snap->state	      = tctx->state;
	snap->hold	      = inf_queue_node_hold(&tctx->qnode);
	snap->joined	      = tctx->joined;
	snap->moving	      = tctx->moving;
	snap->reweight_pending = tctx->reweight_pending;
	snap->dequeue_pending  = tctx->dequeue_pending;
	snap->exit_pending     = tctx->exit_pending;
	snap->last_op	      = op;
	snap->last_src	      = src;
	snap->last_dst	      = dst;
	snap->last_result      = result;

	if (bpf_map_update_elem(&tsnap_stor, &pid, snap, BPF_ANY))
		__sync_fetch_and_add(&ctl->task_overflow, 1);
}

/*
 * Exit-time snapshot of every per-CPU queue. The head pointer is read
 * without the queue lock: a diagnostic record may be stale, and taking a
 * queue lock in the exit path risks a second error.
 */
static __noinline void inf_dump_queues(void)
{
	u32 ncpu = inf_nr_queues;
	u32 cpu;

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		struct inf_queue_snap *qs;
		struct inf_cpu_ctx    *cctx;
		inf_queue_t	      *queue;
		inf_queue_node_t      *head;
		task_ctx	      *tctx;

		if (cpu >= ncpu)
			break;

		qs = bpf_map_lookup_elem(&qsnap_stor, &cpu);
		if (!qs)
			continue;

		queue = inf_queue((s32)cpu);
		cctx  = inf_cpu_ctx((s32)cpu);
		if (!queue || !cctx)
			continue;

		__builtin_memset(qs, 0, sizeof(*qs));
		qs->cpu	  = (s32)cpu;
		qs->depth = READ_ONCE(cctx->depth);
		qs->w_sum = READ_ONCE(cctx->w_sum);

		head	  = inf_queue_first(queue);
		if (!head)
			continue;

		tctx		   = inf_task_from_qnode(head);
		qs->head_pid	   = (s32)tctx->pid;
		qs->head_cpu	   = tctx->queued_cpu;
		qs->head_group_cpu = tctx->group_cpu;
		qs->head_state	   = tctx->state;
		qs->head_hold	   = inf_queue_node_hold(head);
		qs->head_slice	   = tctx->slice_ns;
		qs->head_weight	   = tctx->weight;
		qs->head_key	   = inf_queue_node_key(head);
		{
			struct task_struct *p = bpf_task_from_pid(tctx->pid);

			if (p) {
				qs->head_kflags = p->scx.flags;
				qs->head_ops_state =
					(s64)p->scx.ops_state.counter;
				qs->head_runnable_cpu = p->scx.runnable_cpu;
				bpf_task_release(p);
			}
		}
	}
}

/*
 * Write the exit status of the trace into the control entry, so the
 * loader knows whether the ring ran over before it reads it.
 */
static __noinline void inf_trace_seal(void)
{
	struct inf_trace_ctl *ctl;
	u32		      key = 0;

	ctl			  = bpf_map_lookup_elem(&trace_ctl_stor, &key);
	if (!ctl)
		return;
	WRITE_ONCE(ctl->cap, INF_TRACE_CAP);
	WRITE_ONCE(ctl->enabled, enable_trace ? 1 : 0);
}

/*
 * Record the effective weight a fold produced. The minimum and maximum are
 * the diagnostics for a live cpu.weight or cpu.idle change: a ratio bug
 * shows as an unchanged maximum.
 */
static __always_inline void inf_stats_weight(u64 w)
{
	struct inf_stats *stats = inf_stats();

	if (!stats)
		return;

	__sync_fetch_and_add(&stats->cgrp_eff_samples, 1);
	WRITE_ONCE(stats->cgrp_eff_weight, w);
	if (!READ_ONCE(stats->cgrp_eff_min) ||
	    w < READ_ONCE(stats->cgrp_eff_min))
		WRITE_ONCE(stats->cgrp_eff_min, w);
	if (w > READ_ONCE(stats->cgrp_eff_max))
		WRITE_ONCE(stats->cgrp_eff_max, w);
}

/* Charge the queue before the node becomes visible in it. */
static __always_inline void inf_queue_charge(struct inf_cpu_ctx *cctx, u64 w)
{
	__sync_fetch_and_add(&cctx->w_sum, (s64)w);
	__sync_fetch_and_add(&cctx->depth, 1);
}

/* Release the charge after the node is no longer visible. */
static __always_inline void inf_queue_uncharge(struct inf_cpu_ctx *cctx, u64 w)
{
	s64 prev;

	prev = __sync_fetch_and_add(&cctx->w_sum, -(s64)w);
	if (prev < (s64)w) {
		WRITE_ONCE(cctx->w_sum, 0);
		INF_STAT_INC(lost_state_errors);
	}

	prev = __sync_fetch_and_add(&cctx->depth, -1);
	if (prev <= 0) {
		WRITE_ONCE(cctx->depth, 0);
		INF_STAT_INC(lost_state_errors);
	}
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
	u64 floor;
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
	/*
	 * A task below one tenth of the queue weight takes at least the
	 * 100 us floor, which is itself capped by the base quantum. The
	 * condition mirrors src/policy.rs `quantum_ns()`.
	 */
	floor = base < INF_QUANTUM_FLOOR_NS ? base : INF_QUANTUM_FLOOR_NS;
	if (w * 10 < total && q < floor)
		q = floor;
	return q ? q : 1;
}

/*
 * Effective weight of @p on @cpu through the shared cgroup library. The
 * library folds every cpu.weight level, honours cpu.idle and reports the
 * fixed-point group scale for later reweights.
 *
 * The epoch is read before the fold and stored with the result. A change
 * that lands in the middle of the fold leaves the stored epoch stale, so
 * the next enqueue or dispatch folds again instead of trusting a torn
 * result.
 */
static __always_inline u64 inf_effective_weight(struct task_struct *p, s32 cpu,
						bool joining, task_ctx *tctx)
{
	struct scx_cgroup_weight_info info = {};
	u64			      epoch;
	u64			      w;

	epoch = scx_cgroup_ctl_epoch();
	scx_cgroup_ctl_weight(p, cpu, joining, &info);
	w = info.weight ? info.weight : 1;
	if (w > INF_WEIGHT_CAP)
		w = INF_WEIGHT_CAP;

	if (tctx) {
		tctx->group_scale  = info.scale;
		tctx->idle	   = info.idle;
		tctx->weight_epoch = epoch;
	}
	return w;
}

/*
 * Refold a task whose stored fold predates the current cgroup epoch. The
 * task is already counted in its group, so the fold does not add it again.
 * @cpu must be the CPU the group load is charged to.
 */
static __always_inline u64 inf_refresh_fold(struct task_struct *p, s32 cpu,
					    u64 base, task_ctx *tctx)
{
	struct scx_cgroup_weight_info info = {};
	u64			      epoch;
	u64			      w;

	epoch = scx_cgroup_ctl_epoch();
	scx_cgroup_ctl_weight_refresh(p, cpu, base, &info);
	w = info.weight ? info.weight : 1;
	if (w > INF_WEIGHT_CAP)
		w = INF_WEIGHT_CAP;

	tctx->group_scale  = info.scale;
	tctx->idle	   = info.idle;
	tctx->weight_epoch = epoch;
	INF_STAT_INC(cgrp_refolds);
	inf_stats_weight(w);
	return w;
}

static __always_inline bool inf_weight_stale(task_ctx *tctx)
{
	return tctx->weight_epoch != scx_cgroup_ctl_epoch();
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
	if (base > INF_WEIGHT_CAP)
		base = INF_WEIGHT_CAP;
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
 * Preempt only a fresh wakeup that took a head slot. The reference
 * Infinity 7.2.6-7 policy preempts on the head-arrival condition alone.
 * One consequence is that a lighter newcomer can preempt a heavier
 * victim, because pick order, not weight, decides the wakeup winner. A
 * wakeup that the gate placed on the tail does not preempt, because it is
 * already behind the running task in queue order. The victim must retain
 * more than the configured preemption margin, so a task that is about to
 * expire finishes instead of taking an IPI. A task under a cpu.idle cgroup
 * never preempts.
 */
static __always_inline void inf_maybe_preempt(struct task_struct *p, s32 cpu,
					      u64 enq_flags, bool head)
{
	task_ctx	   *tctx;
	struct task_struct *victim;
	struct inf_stats   *stats;
	u64		    reserve;

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

	{
		struct inf_cfg *cfg = inf_cfg();

		reserve = cfg ? READ_ONCE(cfg->preempt_margin_ns) : 0;
	}
	/* The victim must retain strictly more than the margin. */
	if (READ_ONCE(victim->scx.slice) <= reserve)
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

	TOUCH_ARENA();

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
static __noinline int inf_enqueue_common(struct task_struct *p, u64 enq_flags,
					 bool reenq)
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

	TOUCH_ARENA();

	cpu = scx_bpf_task_cpu(p);
	if (cpu < 0 || (u32)cpu >= inf_nr_cpu_ids())
		cpu = bpf_get_smp_processor_id();
	if (cpu < 0 || (u32)cpu >= inf_nr_cpu_ids())
		return -EINVAL;

	cctx = inf_cpu_ctx(cpu);
	tctx = inf_task_ctx(p);
	if (!cctx) {
		/*
		 * No per-CPU state for the target. Hand the task back so the
		 * core does not keep it in custody with nowhere to run.
		 */
		INF_STAT_INC(enq_no_cctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return 0;
	}
	if (!tctx) {
		/*
		 * The task context is gone: the task already passed
		 * ops.exit_task() but the core enqueued it again (a cgroup
		 * move or the final exit switch). Without a hand-back the
		 * core keeps it queued and the watchdog aborts after the
		 * timeout.
		 */
		INF_STAT_INC(enq_no_ctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return 0;
	}

	stats = inf_stats();
	base  = tctx->base_weight ? tctx->base_weight :
				    (p->scx.weight ? p->scx.weight : 1);

	/*
	 * An exiting task must not wait in the scheduler queue for a later
	 * dispatch: by then its pid can be gone, bpf_task_from_pid() fails,
	 * and the core keeps the task in custody until the watchdog. Hand it
	 * to the local DSQ now, while the task pointer is valid.
	 */
	if ((p->flags & PF_EXITING) || tctx->state == INF_TASK_EXITING) {
		tctx->queued_cpu = -1;
		tctx->state	 = INF_TASK_EXITING;
		inf_trace(INF_TR_EXIT_PASS, tctx, INF_TR_WHERE(cpu, cpu), 3);
		if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0))
			INF_STAT_INC(exit_passes);
		else
			INF_STAT_INC(lost_state_errors);
		return 0;
	}

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
				tctx->joined	= 0;
				tctx->group_cpu = -1;
			}
			if (!scx_cgroup_ctl_put_aside(p, (u64)tctx, 0)) {
				tctx->state	 = INF_TASK_PARKED;
				tctx->queued_cpu = -1;
				if (stats)
					__sync_fetch_and_add(
						&stats->cgrp_throttled, 1);
				inf_trace(INF_TR_ENQ_PARK, tctx,
					  INF_TR_WHERE(cpu, -1), ret);
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
	 * Head-exempt: the SCX_ENQ_HEAD hint only. sched_ext exposes no
	 * curr == se exemption.
	 * Tail: expiry, yield hand-back, requeue, forced progress.
	 * Otherwise the 7:1 gate decides, including a wakeup.
	 */
	if (enq_flags & SCX_ENQ_HEAD) {
		head = true;
	} else if (expired || (enq_flags & (SCX_ENQ_REENQ | SCX_ENQ_LAST |
					    SCX_ENQ_PREEMPT))) {
		head = false;
	} else {
		seq  = __sync_fetch_and_add(&cctx->seq, 1);
		head = !(seq == (u32)-1 ||
			 (seq & INF_GATE_MASK) == INF_GATE_MASK);
	}
	tctx->yielded = 0;

	exempt = expired || (enq_flags & (SCX_ENQ_HEAD | SCX_ENQ_REENQ |
					  SCX_ENQ_LAST | SCX_ENQ_PREEMPT));

	/*
	 * The task claims no queue membership when ops.enqueue() runs. A
	 * stale claim means a previous move did not finish; remove the node
	 * from wherever it claims to be and release that charge before the
	 * new insert, so no task is lost and no weight is charged twice.
	 *
	 * This runs before the fold: the charge to release is the one the
	 * queue took with the stored weight, so the stored weight must still
	 * be the old one.
	 */
	{
		/*
		 * The node link is the source of truth. queued_cpu can lag
		 * behind a move that failed midway, and a linked node that
		 * the bookkeeping forgot makes the insert below fail with
		 * -EALREADY, which used to drop the task.
		 */
		s32		    owner     = inf_queue_owner_cpu(&tctx->qnode);
		s32		    old_cpu   = owner >= 0 ? owner : tctx->queued_cpu;
		struct inf_cpu_ctx *old_cctx  = inf_cpu_ctx(old_cpu);
		inf_queue_t	   *old_queue = inf_queue(old_cpu);
		u64		    old_w = tctx->weight ? tctx->weight : base;
		int		    old_ret;

		if (old_cpu < 0)
			goto no_stale;

		if (old_queue)
			old_ret = inf_queue_remove(old_queue, &tctx->qnode);
		else
			old_ret = -EINVAL;

		if (!old_ret) {
			if (old_cctx)
				inf_queue_uncharge(old_cctx, old_w);
		} else if (old_ret != -EINVAL) {
			/* Still linked behind a busy queue lock. */
			INF_STAT_INC(lost_state_errors);
			inf_trace(INF_TR_ENQ_STALE, tctx,
				  INF_TR_WHERE(old_cpu, cpu), old_ret);
			return -EAGAIN;
		}
		tctx->queued_cpu = -1;
		if (tctx->state == INF_TASK_QUEUED)
			tctx->state = INF_TASK_IDLE;
		inf_trace(INF_TR_ENQ_STALE, tctx, INF_TR_WHERE(old_cpu, cpu),
			  old_ret);
	}
no_stale:

	/*
	 * The task's cgroup load counts it from the first enqueue until the
	 * matching dequeue, so a rotation through expiry does not join twice.
	 * A joined task whose group changed since its last fold refolds here
	 * with joining = false: its own weight is already in the load.
	 */
	if (!tctx->joined) {
		w	     = inf_effective_weight(p, cpu, true, tctx);
		tctx->weight = w;
		scx_cgroup_ctl_join(p, cpu, base);
		tctx->joined	= 1;
		tctx->group_cpu = cpu;
		newly_joined	= true;
		inf_stats_weight(w);
		if (stats)
			stats->cgrp_scale = tctx->group_scale;
	} else {
		bool moved = false;

		/*
		 * The group load is per (cgroup, CPU). A joined task that
		 * arrives on another CPU carries its contribution with it,
		 * because the load on the old CPU no longer describes a
		 * runnable task there. Move it before the fold so the new
		 * level is already correct.
		 */
		if (tctx->group_cpu >= 0 && tctx->group_cpu != cpu) {
			scx_cgroup_ctl_leave(p, tctx->group_cpu, base);
			scx_cgroup_ctl_join(p, cpu, base);
			tctx->group_cpu = cpu;
			moved		= true;
			INF_STAT_INC(cgrp_cpu_moves);
		}

		if (moved || inf_weight_stale(tctx)) {
			w	     = inf_refresh_fold(p, cpu, base, tctx);
			tctx->weight = w;
		} else {
			w = tctx->weight ? tctx->weight : base;
		}
	}

	q   = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
	key = head ? inf_head_key(cctx) : inf_tail_key(cctx);

	/* Charge the queue before the insert so the pop sees this weight. */
	inf_queue_charge(cctx, w);
	if (!inf_queue(cpu)) {
		inf_queue_uncharge(cctx, w);
		if (newly_joined) {
			scx_cgroup_ctl_leave(p, cpu, base);
			tctx->joined = 0;
		}
		INF_STAT_INC(lost_state_errors);
		return -EINVAL;
	}
	ret = inf_queue_insert(inf_queue(cpu), &tctx->qnode, key, q);
	if (ret) {
		inf_queue_uncharge(cctx, w);
		if (newly_joined) {
			scx_cgroup_ctl_leave(p, cpu, base);
			tctx->joined = 0;
		}
		INF_STAT_INC(lost_state_errors);
		inf_trace(INF_TR_ENQ_INSERT_FAIL, tctx, INF_TR_WHERE(-1, cpu),
			  ret);
		return -EINVAL;
	}

	tctx->queued_cpu = cpu;
	tctx->state	 = INF_TASK_QUEUED;
	tctx->slice_ns	 = q;
	inf_trace(INF_TR_INSERT, tctx, INF_TR_WHERE(-1, cpu), head ? 0 : 1);

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

	inf_maybe_preempt(p, cpu, enq_flags, head);
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
__noinline int inf_bw_enqueue(struct task_struct *p __arg_trusted, u64 ctx)
{
	struct inf_stats *stats;

	if (!p || !ctx)
		return 0;

	TOUCH_ARENA();

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
 * The CPU the task may run on, preferring the CPU the core already
 * selected. Returns -1 when the affinity mask contains no known CPU.
 */
static __always_inline s32 inf_task_allowed_cpu(struct task_struct *p,
						s32		    fallback)
{
	struct inf_cpu_topo *t;
	s32		     cpu;

	cpu = scx_bpf_task_cpu(p);
	t   = inf_cpu_topo(cpu);
	if (inf_cpu_allowed(p, t, cpu))
		return cpu;

	cpu = inf_first_allowed(p, false);
	if (cpu >= 0)
		return cpu;

	t = inf_cpu_topo(fallback);
	if (inf_cpu_allowed(p, t, fallback))
		return fallback;
	return -1;
}

/*
 * Put a task that left a queue back on @cpu at the tail. Used when a pop
 * finds a task that cannot run on the popping CPU. The queue lock is not
 * held here.
 */
static __noinline int inf_requeue_task(struct task_struct *p, task_ctx *tctx,
				       s32 cpu)
{
	struct inf_cpu_ctx *cctx;
	inf_queue_t	   *queue;
	u64		    w, q, key;
	int		    ret;

	cctx  = inf_cpu_ctx(cpu);
	queue = inf_queue(cpu);
	if (!cctx || !queue)
		return -EINVAL;

	/* @p may be NULL when the pid lookup failed; use the stored weight. */
	w = tctx->weight;
	if (!w && p)
		w = inf_task_weight(p);
	if (!w)
		w = 1;
	q   = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
	key = inf_tail_key(cctx);

	inf_queue_charge(cctx, w);
	ret = inf_queue_insert(queue, &tctx->qnode, key, q);
	if (ret) {
		inf_queue_uncharge(cctx, w);
		INF_STAT_INC(lost_state_errors);
		/*
		 * Keep the real membership visible when the node is still
		 * linked somewhere, so a later dequeue or exit can find it.
		 */
		if (ret == -EALREADY)
			tctx->queued_cpu = inf_queue_owner_cpu(&tctx->qnode);
		inf_trace(INF_TR_REQUEUE_FAIL, tctx, INF_TR_WHERE(-1, cpu),
			  ret);
		return ret;
	}

	tctx->queued_cpu = cpu;
	tctx->state	 = INF_TASK_QUEUED;
	tctx->slice_ns	 = q;
	INF_STAT_INC(requeues);
	inf_trace(INF_TR_REQUEUE, tctx, INF_TR_WHERE(-1, cpu), 0);

	/*
	 * A requeue from a dispatch callback on this CPU puts the task back
	 * into the scheduler queue after the core already decided there is
	 * nothing to run. Without a kick the CPU goes idle with the task in
	 * our queue and nobody dispatches it. SCX_KICK_IDLE still reschedules
	 * a CPU that is inside dispatch, so one call covers both targets.
	 */
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	return 0;
}

/*
 * Pop the local queue and move the task to the local DSQ. A node whose
 * task is gone, exiting or pending a dequeue is dropped, never run. A
 * task that cannot run on this CPU is requeued on a CPU its mask allows.
 */
static __noinline bool inf_dispatch_local(s32 cpu, struct inf_cpu_ctx *cctx)
{
	inf_queue_t	   *queue = inf_queue(cpu);
	inf_queue_node_t   *node;
	struct task_struct *p;
	task_ctx	   *tctx;
	u64		    nodep, w, q;
	s32		    target;
	bool		    refused = false;

	if (!queue)
		return false;

	nodep = inf_queue_pop(queue, true);
	if (!nodep)
		return false;

	node = (inf_queue_node_t *)nodep;
	tctx = inf_task_from_qnode(node);
	w    = tctx->weight ? tctx->weight : 1;

	/*
	 * Publish the cleared membership before the charge drops, so a
	 * concurrent dequeue does not release the same charge a second time.
	 */
	tctx->queued_cpu = -1;
	inf_queue_uncharge(cctx, w);
	inf_trace(INF_TR_POP, tctx, INF_TR_WHERE(cpu, -1), 0);

	p = bpf_task_from_pid(tctx->pid);
	if (!p) {
		/*
		 * The pid lookup failed, so there is no task pointer to hand
		 * to a DSQ. The core still counts the task as queued: put
		 * the node back and retry on the next dispatch. Dropping it
		 * here stranded a runnable task until the watchdog.
		 */
		INF_STAT_INC(stale_requeues);
		tctx->state = INF_TASK_QUEUED;
		inf_trace(INF_TR_POP_STALE, tctx, INF_TR_WHERE(cpu, -1),
			  -ENOENT);
		if (inf_requeue_task(p, tctx, cpu))
			INF_STAT_INC(lost_state_errors);
		inf_queue_drop(node);
		return false;
	}

	if ((p->flags & PF_EXITING) || tctx->state == INF_TASK_EXITING ||
	    tctx->exit_pending) {
		bool handed;

		/*
		 * An exiting task that the core enqueued (SCX_OPS_ENQ_EXITING)
		 * is still in kernel custody and on the rq runnable list. It
		 * needs CPU time to finish do_exit. Dropping the node here
		 * left it on that list until the watchdog aborted the
		 * scheduler. Hand it to the local DSQ instead; the core
		 * clears custody and the CPU runs the final exit.
		 */
		tctx->state	   = INF_TASK_EXITING;
		tctx->exit_pending = 0;
		tctx->queued_cpu   = -1;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			/* The local DSQ cannot take a task this CPU may not run. */
			target = inf_task_allowed_cpu(p, cpu);
			if (target >= 0 && !inf_requeue_task(p, tctx, target)) {
				inf_trace(INF_TR_EXIT_PASS, tctx,
					  INF_TR_WHERE(cpu, target), 2);
			} else {
				INF_STAT_INC(lost_state_errors);
			}
			bpf_task_release(p);
			inf_queue_drop(node);
			return false;
		}

		q	       = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
		tctx->slice_ns = q;
		scx_bpf_task_set_slice(p, q);
		handed = scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, q, 0);
		inf_trace(INF_TR_EXIT_PASS, tctx, INF_TR_WHERE(cpu, cpu),
			  handed ? 1 : 0);
		if (!handed)
			INF_STAT_INC(lost_state_errors);
		else
			INF_STAT_INC(exit_passes);
		bpf_task_release(p);
		inf_queue_drop(node);
		return handed;
	}

	if (tctx->dequeue_pending) {
		tctx->dequeue_pending = 0;
		tctx->state	      = INF_TASK_IDLE;
		bpf_task_release(p);
		inf_queue_drop(node);
		INF_STAT_INC(stale_pops);
		inf_trace(INF_TR_POP_PENDING, tctx, INF_TR_WHERE(cpu, -1), 0);
		return false;
	}

	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		target = inf_task_allowed_cpu(p, cpu);
		if (target >= 0)
			inf_requeue_task(p, tctx, target);
		else
			INF_STAT_INC(lost_state_errors);
		inf_trace(INF_TR_POP_AFFINITY, tctx, INF_TR_WHERE(cpu, target),
			  0);
		bpf_task_release(p);
		inf_queue_drop(node);
		return false;
	}

	/*
	 * The pop released the old charge. A task whose group changed since
	 * its last fold gets the new weight before its slice is computed, so
	 * the first quantum after a live cpu.weight or cpu.idle change is
	 * already correct.
	 */
	if (inf_weight_stale(tctx)) {
		u64 base = tctx->base_weight ?
				   tctx->base_weight :
				   (p->scx.weight ? p->scx.weight : 1);

		w	 = inf_refresh_fold(
			p, tctx->group_cpu >= 0 ? tctx->group_cpu : cpu, base,
			tctx);
		tctx->weight = w;
	}

	/* The task is out of the queue, so the remaining weight normalizes. */
	q		       = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
	tctx->queued_cpu       = -1;
	tctx->state	       = INF_TASK_DISPATCHED;
	tctx->slice_ns	       = q;
	tctx->reweight_pending = 0;

	scx_bpf_task_set_slice(p, q);
	if (inject_dsq_refusal) {
		struct inf_test_ctl *tc;
		u32		     tkey = 0;

		tc = bpf_map_lookup_elem(&test_stor, &tkey);
		if (tc && READ_ONCE(tc->dsq_refuse)) {
			__sync_fetch_and_add(&tc->dsq_refuse, -1);
			refused = true;
		}
	}
	if (refused || !scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, q, 0)) {
		/*
		 * The core refused the local insert. Put the node back on
		 * this CPU instead of dropping a runnable task.
		 */
		tctx->state = INF_TASK_IDLE;
		inf_trace(INF_TR_DSQ_REFUSED, tctx, INF_TR_WHERE(cpu, cpu),
			  refused ? 1 : 0);
		if (inf_requeue_task(p, tctx, cpu))
			INF_STAT_INC(lost_state_errors);
		bpf_task_release(p);
		inf_queue_drop(node);
		return false;
	}
	inf_trace(INF_TR_DSQ_OK, tctx, INF_TR_WHERE(cpu, cpu), 0);

	bpf_task_release(p);
	inf_queue_drop(node);
	return true;
}

/*
 * Steal the head of one peer queue. The peek holds the node before the
 * queue lock is released; the node stays held until after the local DSQ
 * insert, so the task context cannot be freed underneath us. No DSQ call
 * runs while the peer queue lock is held.
 */
static __noinline bool inf_steal_from(s32 peer, s32 dst,
				      struct inf_cpu_ctx *dcctx)
{
	struct inf_cpu_ctx  *pcctx = inf_cpu_ctx(peer);
	struct inf_cpu_topo *pt	   = inf_cpu_topo(dst);
	inf_queue_t	    *pq	   = inf_queue(peer);
	inf_queue_node_t    *node;
	struct task_struct  *p;
	task_ctx	    *tctx;
	u64		     nodep, w, q;

	if (!pcctx || !pt || !pq)
		return false;

	nodep = inf_queue_peek_hold(pq);
	if (!nodep)
		return false;

	node = (inf_queue_node_t *)nodep;
	tctx = inf_task_from_qnode(node);
	w    = tctx->weight ? tctx->weight : 1;

	p    = bpf_task_from_pid(tctx->pid);
	if (!p) {
		/*
		 * No task pointer to hand over. Leave the node in the peer
		 * queue; the peer dispatch retries. Dropping it here would
		 * strand a task the core still counts as queued.
		 */
		inf_queue_drop(node);
		INF_STAT_INC(stale_skips);
		return false;
	}

	if ((p->flags & PF_EXITING) || tctx->state == INF_TASK_EXITING) {
		bool handed;
		int  removed;

		removed = inf_queue_try_remove(pq, node);
		if (removed) {
			/*
			 * The peer lock was busy. The node is still linked
			 * in the peer queue: leave it there and let that
			 * CPU's dispatch hand it back. Clearing the
			 * membership here would corrupt the bookkeeping.
			 */
			bpf_task_release(p);
			inf_queue_drop(node);
			return false;
		}
		tctx->queued_cpu = -1;
		inf_queue_uncharge(pcctx, w);

		/*
		 * Same rule as the local pop: an exiting task in kernel
		 * custody is handed to a DSQ. Requeueing it to the peer
		 * would repeat the stall when that CPU is idle.
		 */
		tctx->state	 = INF_TASK_EXITING;
		tctx->queued_cpu = -1;

		if (!inf_cpu_allowed(p, pt, dst)) {
			if (!inf_requeue_task(p, tctx, peer)) {
				inf_trace(INF_TR_EXIT_PASS, tctx,
					  INF_TR_WHERE(peer, peer), 2);
			} else {
				INF_STAT_INC(lost_state_errors);
			}
			bpf_task_release(p);
			inf_queue_drop(node);
			return false;
		}

		q	       = inf_quantum(w, READ_ONCE(dcctx->w_sum) + w);
		tctx->slice_ns = q;
		scx_bpf_task_set_slice(p, q);
		handed = scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, q, 0);
		inf_trace(INF_TR_EXIT_PASS, tctx, INF_TR_WHERE(peer, dst),
			  handed ? 1 : 0);
		if (handed)
			INF_STAT_INC(exit_passes);
		else
			INF_STAT_INC(lost_state_errors);
		bpf_task_release(p);
		inf_queue_drop(node);
		return handed;
	}

	if (tctx->dequeue_pending || tctx->exit_pending) {
		if (!inf_queue_try_remove(pq, node)) {
			tctx->queued_cpu = -1;
			inf_queue_uncharge(pcctx, w);
		}
		tctx->dequeue_pending = 0;
		tctx->exit_pending    = 0;
		bpf_task_release(p);
		inf_queue_drop(node);
		INF_STAT_INC(stale_pops);
		return false;
	}

	/* A head that cannot run here is skipped, not bypassed. */
	if (!inf_cpu_allowed(p, pt, dst)) {
		bpf_task_release(p);
		inf_queue_drop(node);
		return false;
	}

	if (inf_queue_try_remove(pq, node)) {
		bpf_task_release(p);
		inf_queue_drop(node);
		return false;
	}

	tctx->queued_cpu = -1;
	inf_queue_uncharge(pcctx, w);

	/* The peer pop released the old charge; refold before the slice. */
	if (inf_weight_stale(tctx)) {
		u64 base = tctx->base_weight ?
				   tctx->base_weight :
				   (p->scx.weight ? p->scx.weight : 1);

		w	 = inf_refresh_fold(
			p, tctx->group_cpu >= 0 ? tctx->group_cpu : peer, base,
			tctx);
		tctx->weight = w;
	}

	tctx->state    = INF_TASK_DISPATCHED;
	q	       = inf_quantum(w, READ_ONCE(dcctx->w_sum) + w);
	tctx->slice_ns = q;

	scx_bpf_task_set_slice(p, q);
	if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, q, 0)) {
		/*
		 * The destination refused the insert. Return the task to
		 * the source queue; never drop a runnable task here.
		 */
		tctx->state = INF_TASK_IDLE;
		if (inf_requeue_task(p, tctx, peer))
			INF_STAT_INC(lost_state_errors);
		bpf_task_release(p);
		inf_queue_drop(node);
		return false;
	}
	bpf_task_release(p);
	inf_queue_drop(node);
	INF_STAT_INC(steals);
	return true;
}

/*
 * One steal tier: at most eight eligible peers, starting at the cursor
 * and wrapping. The cursor advances past every examined peer, so the next
 * dispatch starts where this one stopped.
 */
static __noinline bool inf_steal_tier(s32 cpu, u32 llc, u32 node, u32 tier,
				      u32 *cursor, struct inf_cpu_ctx *dcctx)
{
	u32 ncpu = inf_nr_cpu_ids();
	u32 start, next;
	s32 i, examined = 0;

	if (!ncpu)
		return false;

	start = READ_ONCE(*cursor);
	if (start >= ncpu)
		start = 0;
	next = start;

	bpf_for(i, 0, INF_STEAL_SCAN_CPUS)
	{
		struct inf_cpu_topo *pt;
		u32		     peer;

		if ((u32)i >= ncpu || examined >= INF_STEAL_MAX_PEERS)
			break;

		peer = start + (u32)i;
		if (peer >= ncpu)
			peer -= ncpu;
		if ((s32)peer == cpu)
			continue;

		pt = inf_cpu_topo((s32)peer);
		if (!pt || !pt->online)
			continue;
		if (tier == INF_STEAL_LLC) {
			if (pt->llc_id != llc)
				continue;
		} else {
			/* The node tier excludes the local LLC. */
			if (pt->node_id != node || pt->llc_id == llc)
				continue;
		}

		examined++;
		next = peer + 1;
		if (next >= ncpu)
			next = 0;

		if (inf_steal_from((s32)peer, cpu, dcctx)) {
			WRITE_ONCE(*cursor, next);
			if (tier == INF_STEAL_LLC) {
				INF_STAT_INC(steal_llc);
			} else {
				INF_STAT_INC(steal_node);
			}
			return true;
		}
	}

	WRITE_ONCE(*cursor, next);
	return false;
}

/*
 * Dispatch: the local queue first, then same-LLC peers, then same-NUMA
 * peers outside the local LLC. If nothing is runnable, renew the previous
 * task in place when its slice expired.
 */
void BPF_STRUCT_OPS(infinity_dispatch, s32 cpu, struct task_struct *prev)
{
	struct inf_cpu_ctx  *cctx;
	struct inf_cpu_topo *lt;
	task_ctx	    *tctx = NULL;
	u64		     q, w;

	TOUCH_ARENA();

	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	/* Re-enqueue backlogged tasks of cgroups that got time again. */
	if (inf_cpu_bw_enabled())
		scx_cgroup_ctl_reenqueue();

	if (inf_dispatch_local(cpu, cctx))
		return;

	lt = inf_cpu_topo(cpu);
	if (lt && lt->online) {
		if (inf_steal_tier(cpu, lt->llc_id, lt->node_id, INF_STEAL_LLC,
				   &cctx->steal_llc_cursor, cctx))
			return;
		if (inf_steal_tier(cpu, lt->llc_id, lt->node_id, INF_STEAL_NODE,
				   &cctx->steal_node_cursor, cctx))
			return;
	}

	/*
	 * The queues are empty and the previous task is still runnable with
	 * no slice left. Renew it in place instead of waiting for a round
	 * trip through enqueue.
	 */
	if (prev && !READ_ONCE(prev->scx.slice)) {
		tctx = inf_task_ctx(prev);
		w = tctx && tctx->weight ? tctx->weight : inf_task_weight(prev);
		q = inf_quantum(w, READ_ONCE(cctx->w_sum) + w);
		scx_bpf_task_set_slice(prev, q);
	}

	inf_trace(INF_TR_DISPATCH_EMPTY, tctx, INF_TR_WHERE(cpu, -1),
		  prev ? 0 : -ENOENT);
}

/* Remove a queued task from its queue and release the charge once. */
static __noinline void inf_remove_queued(struct task_struct *p, task_ctx *tctx)
{
	struct inf_cpu_ctx *cctx;
	inf_queue_t	   *queue;
	u64		    w;
	s32		    cpu = tctx->queued_cpu;
	int		    ret;

	if (cpu < 0)
		return;

	queue = inf_queue(cpu);
	cctx  = inf_cpu_ctx(cpu);
	w     = tctx->weight ? tctx->weight : inf_task_weight(p);

	if (queue)
		ret = inf_queue_remove(queue, &tctx->qnode);
	else
		ret = -EINVAL;

	if (!ret) {
		if (cctx)
			inf_queue_uncharge(cctx, w);
		tctx->queued_cpu = -1;
		if (tctx->state == INF_TASK_QUEUED)
			tctx->state = INF_TASK_IDLE;
		inf_trace(INF_TR_REMOVE, tctx, INF_TR_WHERE(cpu, -1), 0);
	} else if (ret == -EINVAL) {
		/*
		 * The node is not linked. The path that unlinked it also
		 * released its charge, so this path must not release it a
		 * second time.
		 */
		tctx->queued_cpu = -1;
		if (tctx->state == INF_TASK_QUEUED)
			tctx->state = INF_TASK_IDLE;
		inf_trace(INF_TR_REMOVE, tctx, INF_TR_WHERE(cpu, -1), ret);
	} else {
		/* The lock timed out and the node is still linked. */
		INF_STAT_INC(lost_state_errors);
		inf_trace(INF_TR_REMOVE_FAIL, tctx, INF_TR_WHERE(cpu, -1), ret);
	}
}

/*
 * A dequeue or exit arrived while a mover held the task. The mover owns
 * the queue operation, so it applies the pending state before it clears
 * the moving flag.
 */
static __noinline void inf_resolve_pending(struct task_struct *p,
					   task_ctx	      *tctx)
{
	if (!tctx->dequeue_pending && !tctx->exit_pending)
		return;

	inf_remove_queued(p, tctx);

	if (tctx->exit_pending)
		tctx->state = INF_TASK_EXITING;
	tctx->dequeue_pending = 0;
	tctx->exit_pending    = 0;
}

void BPF_STRUCT_OPS(infinity_dequeue, struct task_struct *p, u64 deq_flags)
{
	task_ctx *tctx;
	bool	  core_exec, ended;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Count the reason before the lifecycle decision. The counters are the
	 * runtime proof for the group-load rule: only a sleep or a property
	 * change ends the runnable period.
	 */
	if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		INF_STAT_INC(deq_core_sched_exec);
	else if (deq_flags & SCX_DEQ_SLEEP)
		INF_STAT_INC(deq_sleep);
	else if (deq_flags & SCX_DEQ_SCHED_CHANGE)
		INF_STAT_INC(deq_sched_change);
	else
		INF_STAT_INC(deq_keep);

	/*
	 * Only a sleep or a property change ends the runnable period. A
	 * core-scheduled execution and the flags-0 custody transfer of this
	 * kernel both leave a runnable task that is no longer in BPF custody,
	 * so its group load must stay: a running task that left the load made
	 * both groups look empty and equal shares followed.
	 */
	core_exec = !!(deq_flags & SCX_DEQ_CORE_SCHED_EXEC);
	ended	  = !core_exec &&
		    (deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_SCHED_CHANGE));

	if (ended && tctx->joined) {
		scx_cgroup_ctl_leave(p, tctx->group_cpu, tctx->base_weight);
		tctx->joined	= 0;
		tctx->group_cpu = -1;
	}

	if (tctx->queued_cpu >= 0) {
		if (cmpxchg(&tctx->moving, 0, 1)) {
			tctx->dequeue_pending = 1;
			inf_trace(INF_TR_DEQ_PENDING, tctx,
				  INF_TR_WHERE(tctx->queued_cpu, -1),
				  deq_flags);
			return;
		}
		inf_remove_queued(p, tctx);
		tctx->dequeue_pending = 0;
		tctx->moving	      = 0;
		inf_trace(INF_TR_DEQ_QUEUED, tctx,
			  INF_TR_WHERE(tctx->queued_cpu, -1), deq_flags);
	} else {
		inf_trace(INF_TR_DEQ_END, tctx, INF_TR_WHERE(-1, -1),
			  deq_flags);
	}

	/*
	 * SCX_DEQ_CORE_SCHED_EXEC means the core ran a task that was still
	 * queued. It stays runnable, so it moves to RUNNING. A sleep or a
	 * property change ends the runnable period. A custody-only dequeue
	 * keeps the state the dispatch or running hook set.
	 */
	if (core_exec)
		tctx->state = INF_TASK_RUNNING;
	else if (ended && tctx->state != INF_TASK_EXITING)
		tctx->state = INF_TASK_IDLE;
}

/*
 * The core calls ops.quiescent() when a task leaves the runqueue for any
 * reason. A task that the scheduler already dispatched is no longer in BPF
 * custody, so ops.dequeue() does not run for it: this is the only callback
 * that sees a running task go to sleep. End the runnable period here once,
 * as the state table requires. A dequeue that already dropped the load
 * cleared @joined, so this is idempotent.
 */
void BPF_STRUCT_OPS(infinity_quiescent, struct task_struct *p, u64 deq_flags)
{
	task_ctx *tctx;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	if (deq_flags & SCX_DEQ_SLEEP)
		INF_STAT_INC(q_sleep);
	else if (deq_flags & SCX_DEQ_SCHED_CHANGE)
		INF_STAT_INC(q_sched_change);
	else
		INF_STAT_INC(q_keep);

	/*
	 * A core-scheduled execution and the flags-0 custody transfer both
	 * leave a runnable task that is only out of BPF custody, so the group
	 * load must stay. Only a sleep or a property change ends the runnable
	 * period; a dequeue that already ran cleared @joined, so this is
	 * idempotent.
	 */
	if (!(deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_SCHED_CHANGE)))
		return;

	if (!tctx->joined)
		return;

	scx_cgroup_ctl_leave(p, tctx->group_cpu, tctx->base_weight);
	tctx->joined	= 0;
	tctx->group_cpu = -1;
	if (tctx->state != INF_TASK_EXITING && tctx->state != INF_TASK_QUEUED)
		tctx->state = INF_TASK_IDLE;
}

void BPF_STRUCT_OPS(infinity_set_weight, struct task_struct *p, u32 weight)
{
	struct inf_cpu_ctx *cctx;
	inf_queue_t	   *queue;
	inf_queue_node_t   *node;
	task_ctx	   *tctx;
	u64		    old_base, new_base, old, new, old_key, key;
	u32		    seq;
	s32		    cpu;
	bool		    head;
	int		    ret;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	INF_STAT_INC(weight_changes);
	inf_trace(INF_TR_SET_WEIGHT, tctx, INF_TR_WHERE(tctx->queued_cpu, -1),
		  (s64)weight);

	old_base	  = tctx->base_weight;
	new_base	  = weight ? weight : 1;
	old		  = tctx->weight;
	tctx->base_weight = new_base;

	/*
	 * A group change since the last fold makes the stored scale stale.
	 * Refold with the new base now; otherwise apply the new base to the
	 * stored scale. Either way the value is stored before the queue
	 * charge moves, so a pop never sees a weight the queue did not take.
	 */
	if (inf_weight_stale(tctx)) {
		s32 fcpu = tctx->group_cpu >= 0 ? tctx->group_cpu :
						  tctx->queued_cpu;

		if (fcpu < 0)
			fcpu = scx_bpf_task_cpu(p);
		new = inf_refresh_fold(p, fcpu, new_base, tctx);
	} else {
		new = inf_reweight(new_base, tctx->group_scale, tctx->idle);
	}
	tctx->weight   = new;
	tctx->slice_ns = inf_quantum(new, new);

	if (tctx->joined)
		scx_cgroup_ctl_reweight(p, tctx->group_cpu, old_base, new_base);

	cpu = tctx->queued_cpu;
	if (cpu < 0)
		return;

	INF_STAT_INC(weight_queued_cpu);

	queue = inf_queue(cpu);
	cctx  = inf_cpu_ctx(cpu);
	if (!queue || !cctx)
		return;

	/*
	 * The queue holds a charge for the old weight. Move it to the new
	 * weight before any return that leaves the node in place, so a later
	 * pop never subtracts a weight the queue did not hold.
	 */
	if (tctx->state != INF_TASK_QUEUED) {
		__sync_fetch_and_add(&cctx->w_sum, (s64)new - (s64)old);
		return;
	}

	INF_STAT_INC(reweight_queued);

	/*
	 * Take a hold before claiming the mover slot. A concurrent exit
	 * waits for this hold, so the context survives until the move
	 * finishes even if the exit wins the race.
	 */
	node = &tctx->qnode;
	inf_queue_hold(node);

	/*
	 * A concurrent mover owns the node. Defer the move; the task is
	 * leaving the queue anyway, and the new weight is already stored.
	 */
	if (cmpxchg(&tctx->moving, 0, 1)) {
		tctx->reweight_pending = 1;
		__sync_fetch_and_add(&cctx->w_sum, (s64)new - (s64)old);
		inf_queue_drop(node);
		return;
	}

	old_key = inf_queue_node_key(node);

	ret	= inf_queue_remove(queue, node);
	if (ret) {
		tctx->moving = 0;
		inf_queue_drop(node);
		INF_STAT_INC(lost_state_errors);
		return;
	}

	inf_queue_uncharge(cctx, old);

	/* A reweight is a normal gate step: it consumes one sequence slot. */
	seq  = __sync_fetch_and_add(&cctx->seq, 1);
	head = !(seq == (u32)-1 || (seq & INF_GATE_MASK) == INF_GATE_MASK);
	key  = head ? inf_head_key(cctx) : inf_tail_key(cctx);
	tctx->slice_ns = inf_quantum(new, READ_ONCE(cctx->w_sum) + new);

	inf_queue_charge(cctx, new);
	ret = inf_queue_insert(queue, node, key, tctx->slice_ns);
	if (ret) {
		inf_queue_uncharge(cctx, new);

		/* Put the node back where it was and keep the old weight. */
		inf_queue_charge(cctx, old);
		if (inf_queue_insert(queue, node, old_key, tctx->slice_ns)) {
			inf_queue_uncharge(cctx, old);
			tctx->queued_cpu = -1;
			if (inf_requeue_task(p, tctx, cpu))
				INF_STAT_INC(lost_state_errors);
		}
		tctx->moving = 0;
		inf_queue_drop(node);
		return;
	}

	tctx->queued_cpu       = cpu;
	tctx->state	       = INF_TASK_QUEUED;
	tctx->reweight_pending = 0;
	inf_resolve_pending(p, tctx);
	tctx->moving = 0;
	inf_queue_drop(node);
	INF_STAT_INC(reweight_moves);
	inf_trace(INF_TR_REWEIGHT, tctx, INF_TR_WHERE(cpu, cpu), 0);
}

/*
 * Move a runnable queued target to the head of its own queue. The weight
 * and the queue membership do not change, so neither the weight sum nor
 * the 7:1 gate advances. A target that is running, in a local DSQ,
 * throttled, exiting or not queued is refused.
 */
static __noinline bool inf_yield_to(struct task_struct *from,
				    struct task_struct *to)
{
	struct inf_cpu_ctx *cctx;
	inf_queue_t	   *queue;
	inf_queue_node_t   *node;
	task_ctx	   *tctx;
	u64		    old_key, key, slice, w;
	s32		    tcpu;
	int		    ret;

	if (!to || to == from)
		return false;
	if (to->flags & PF_EXITING)
		return false;
	if (scx_bpf_task_running(to))
		return false;

	tctx = inf_task_ctx(to);
	if (!tctx)
		return false;
	if (tctx->state != INF_TASK_QUEUED || tctx->queued_cpu < 0)
		return false;

	tcpu = tctx->queued_cpu;
	/* A task in a sched_ext local DSQ is not in our queue. */
	if (to == __COMPAT_scx_bpf_cpu_curr(tcpu))
		return false;

	queue = inf_queue(tcpu);
	cctx  = inf_cpu_ctx(tcpu);
	if (!queue || !cctx)
		return false;

	/* One writer owns the node. A lost race is a refusal, not a move. */
	node = &tctx->qnode;
	inf_queue_hold(node);
	if (cmpxchg(&tctx->moving, 0, 1)) {
		inf_queue_drop(node);
		return false;
	}

	old_key = inf_queue_node_key(node);
	slice	= tctx->slice_ns ? tctx->slice_ns : 1;
	w	= tctx->weight ? tctx->weight : 1;

	ret	= inf_queue_remove(queue, node);
	if (ret) {
		if (ret == -EINVAL) {
			/*
			 * The node was already unlinked and its charge was
			 * released by that path. Only the membership and
			 * the state remain to be cleared.
			 */
			tctx->queued_cpu = -1;
			tctx->state	 = INF_TASK_IDLE;
		} else {
			INF_STAT_INC(lost_state_errors);
		}
		tctx->moving = 0;
		inf_queue_drop(node);
		return false;
	}

	/*
	 * The newest head key, without a gate step: the target runs before
	 * every queued head and tail task and the 7:1 ratio is unchanged.
	 */
	key = inf_head_key(cctx);
	if (inf_queue_insert(queue, node, key, slice)) {
		if (inf_queue_insert(queue, node, old_key, slice)) {
			/* Put the task back at the tail rather than lose it. */
			inf_queue_uncharge(cctx, w);
			tctx->queued_cpu = -1;
			tctx->state	 = INF_TASK_IDLE;
			if (inf_requeue_task(to, tctx, tcpu))
				INF_STAT_INC(lost_state_errors);
		}
		tctx->moving = 0;
		inf_queue_drop(node);
		return false;
	}

	tctx->queued_cpu = tcpu;
	tctx->state	 = INF_TASK_QUEUED;
	inf_resolve_pending(to, tctx);
	tctx->moving = 0;
	inf_queue_drop(node);
	INF_STAT_INC(yield_to_moves);
	inf_trace(INF_TR_YIELD_TO, tctx, INF_TR_WHERE(tcpu, tcpu), 0);
	return true;
}

bool BPF_STRUCT_OPS(infinity_yield, struct task_struct *from,
		    struct task_struct *to)
{
	task_ctx *tctx;
	bool	  moved = false;

	TOUCH_ARENA();

	if (!from)
		return false;

	/* Yield forfeits the remaining slice; the core re-enqueues. */
	scx_bpf_task_set_slice(from, 0);
	tctx = inf_task_ctx(from);
	if (tctx)
		tctx->yielded = 1;

	if (to && to != from)
		moved = inf_yield_to(from, to);

	INF_STAT_INC(yields);

	return moved;
}

void BPF_STRUCT_OPS(infinity_running, struct task_struct *p)
{
	task_ctx *tctx;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (tctx) {
		tctx->last_running_ns = scx_bpf_now();
		tctx->state	      = INF_TASK_RUNNING;
	}
}

void BPF_STRUCT_OPS(infinity_stopping, struct task_struct *p, bool runnable)
{
	task_ctx *tctx;
	u64	  now, delta;

	(void)runnable;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
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

	TOUCH_ARENA();

	tctx = inf_task_ctx_alloc(p);
	if (!tctx)
		return -ENOMEM;

	/* Zero the whole context, then seed the live fields. */
	bpf_for(i, 0, (int)sizeof(*tctx))
	{
		((char __arena *)tctx)[i] = 0;
	}

	/* The queue node starts detached with a zero hold count. */
	if (inf_queue_node_init(&tctx->qnode)) {
		scx_task_free_rcu(p);
		return -EINVAL;
	}

	tctx->base_weight      = p->scx.weight ? p->scx.weight : 1;
	tctx->weight	       = tctx->base_weight;
	tctx->group_scale      = SCX_CGROUP_WEIGHT_ONE;
	tctx->slice_ns	       = 0;
	tctx->last_running_ns  = scx_bpf_now();
	tctx->weight_epoch     = 0;
	tctx->queued_cpu       = -1;
	tctx->group_cpu	       = -1;
	tctx->state	       = INF_TASK_IDLE;
	tctx->moving	       = 0;
	tctx->reweight_pending = 0;
	tctx->dequeue_pending  = 0;
	tctx->exit_pending     = 0;
	tctx->joined	       = 0;
	tctx->yielded	       = 0;
	tctx->wake_fork	       = 0;
	tctx->idle	       = 0;
	tctx->pid	       = p->pid;
	return 0;
}

s32 BPF_STRUCT_OPS(infinity_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	struct inf_cpu_ctx *cctx;
	task_ctx	   *tctx;
	u64		    w;
	s32		    cpu;
	int		    ret;

	(void)args;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx) {
		scx_task_free_rcu(p);
		return 0;
	}

	tctx->state = INF_TASK_EXITING;

	if (tctx->joined) {
		scx_cgroup_ctl_leave(p, tctx->group_cpu, tctx->base_weight);
		tctx->joined	= 0;
		tctx->group_cpu = -1;
	}

	/*
	 * Remove the task from its scheduler queue and release the charge
	 * only when this path wins the unlink. A concurrent mover has
	 * already released it.
	 */
	cpu = tctx->queued_cpu;
	if (cpu >= 0) {
		inf_queue_t *queue = inf_queue(cpu);

		cctx		   = inf_cpu_ctx(cpu);
		w = tctx->weight ? tctx->weight : inf_task_weight(p);
		if (queue && !inf_queue_remove(queue, &tctx->qnode)) {
			if (cctx)
				inf_queue_uncharge(cctx, w);
			tctx->queued_cpu = -1;
		} else if (queue) {
			/* -EINVAL: already unlinked. The charge is gone too. */
			tctx->queued_cpu = -1;
		}
	}

	/*
	 * Unlink any remaining node and wait for the last pop or steal
	 * hold. A non-zero return means a hold never dropped; leak the
	 * context rather than free memory another CPU may still use.
	 */
	ret = inf_queue_node_detach(&tctx->qnode);
	if (ret) {
		scx_bpf_error("infinity: queue detach failed for pid %d: %d",
			      p->pid, ret);
		return 0;
	}

	/*
	 * Mark the task dead in the bandwidth queues before freeing the
	 * context; concurrent drains holding the task must finish.
	 */
	if (inf_cpu_bw_enabled())
		scx_cgroup_ctl_cancel((u64)tctx, SCX_CGROUP_BW_CANCEL_DROP);

	/*
	 * A run-time exit drops the snapshot, so the table holds only live
	 * tasks and cannot fill under fork load. During teardown every task
	 * passes here, including a stranded one, so keep the snapshots for
	 * the exit dump.
	 */
	if (!inf_shutting_down) {
		s32 pid = (s32)tctx->pid;

		bpf_map_delete_elem(&tsnap_stor, &pid);
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
	u64			      epoch;
	int			      ret;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	epoch = scx_cgroup_ctl_epoch();
	ret   = scx_cgroup_ctl_move(p, (u64)tctx, from, to, tctx->group_cpu,
				    tctx->base_weight, tctx->joined != 0);
	if (ret)
		scx_bpf_error("Failed to move a task between cgroups: %d", ret);

	/*
	 * The task is now accounted on the new path; refresh the folded
	 * weight for its next quantum from the destination cgroup, which the
	 * task's own pointer may not name yet.
	 */
	if (tctx->joined) {
		scx_cgroup_ctl_weight_fold(to, tctx->group_cpu,
					   tctx->base_weight, false, &info);
		tctx->weight = info.weight ? info.weight : 1;
		if (tctx->weight > INF_WEIGHT_CAP)
			tctx->weight = INF_WEIGHT_CAP;
		tctx->group_scale  = info.scale;
		tctx->idle	   = info.idle;
		tctx->weight_epoch = epoch;
		inf_stats_weight(tctx->weight);
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
	u32 key, pages;
	s32 cpu;
	int ret;

	TOUCH_ARENA();

	if (ncpu > INF_MAX_CPUS)
		ncpu = INF_MAX_CPUS;
	if (!ncpu) {
		scx_bpf_error("infinity: no possible CPUs");
		return -EINVAL;
	}

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
	 * One scheduler-owned queue per possible CPU. The block lives in
	 * the BPF arena and is never resized; a CPU index selects an entry.
	 * The arena frees the whole block when the map is destroyed.
	 */
	pages = (ncpu * (u32)sizeof(*inf_queues) + PAGE_SIZE - 1) / PAGE_SIZE;
	inf_queues =
		bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!inf_queues) {
		scx_bpf_error("infinity: failed to allocate %u queue pages",
			      pages);
		return -ENOMEM;
	}
	inf_nr_queues = ncpu;
	inf_trace_seal();

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		if ((u32)cpu >= ncpu)
			break;
		inf_queue_init(&inf_queues[cpu]);
	}

	/* Array maps start zeroed. Seed both key runs before any enqueue. */
	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		if (cpu < 0)
			continue;
		key  = (u32)cpu;
		cctx = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cctx) {
			cctx->head_seq		= INF_KEY_MID;
			cctx->tail_seq		= INF_KEY_MID;
			cctx->w_sum		= 0;
			cctx->depth		= 0;
			cctx->seq		= 0;
			cctx->steal_llc_cursor	= 0;
			cctx->steal_node_cursor = 0;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(infinity_disable, struct task_struct *p)
{
	(void)p;
	inf_shutting_down = true;
}

void BPF_STRUCT_OPS(infinity_exit, struct scx_exit_info *ei)
{
	TOUCH_ARENA();

	/*
	 * Snapshot the queues while the arena still owns them, so the exit
	 * dump names the queue and task state of a stalled run.
	 */
	inf_dump_queues();
	inf_trace_seal();

	/*
	 * The arena owns the queue block. Drop the scheduler pointer before
	 * the map is destroyed; no callback runs after ops.exit().
	 */
	inf_queues    = NULL;
	inf_nr_queues = 0;
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(infinity_ops, .select_cpu = (void *)infinity_select_cpu,
	       .enqueue		     = (void *)infinity_enqueue,
	       .dispatch	     = (void *)infinity_dispatch,
	       .dequeue		     = (void *)infinity_dequeue,
	       .running		     = (void *)infinity_running,
	       .stopping	     = (void *)infinity_stopping,
	       .quiescent	     = (void *)infinity_quiescent,
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
	       .disable		     = (void *)infinity_disable,
	       .init = (void *)infinity_init, .exit = (void *)infinity_exit,
	       .flags	   = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .timeout_ms = 20000, .name = "infinity");
