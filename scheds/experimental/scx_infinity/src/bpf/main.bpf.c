/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_infinity core policy: the revision-4 hierarchical entity tree.
 *
 * Each CPU owns one entity tree. The tree has a root entity, one group
 * entity per (cgroup, CPU) pair and one task entity per task. The direct
 * tasks of a cgroup and the child cgroup entities are siblings in one
 * eligible deadline queue, ordered by the normalized service value of the
 * children.
 *
 * The service value is a Q16 nanosecond count. Every entity advances its
 * own value by the runtime it received, divided by its own weight, and
 * keeps the division remainder. A parent queue keeps a monotone frontier
 * and a 7:1 gate that decides whether an insertion takes the head or the
 * tail of that queue.
 *
 * A dispatch descends from the root, filters every level to the service
 * band, and picks the newest eligible head or the oldest eligible tail.
 * The selected leaf task goes into the local DSQ, and its whole path
 * leaves the tree until the slot ends.
 *
 * A sched_ext local DSQ runs only the task the scheduler selected. The
 * scheduler never uses a DSQ as the ready queue, so tree membership,
 * holds, removal and ordering stay under scheduler control.
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
 * The live control state of every cgroup, keyed by the cgroup id. The
 * scheduler reads it when it latches a group weight and when it refreshes
 * one at an epoch boundary. A cgroup without an entry has no entity.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, INF_MAX_CGROUPS);
	__type(key, u64);
	__type(value, struct inf_cgrp_state);
} cgrp_state_stor SEC(".maps");

/*
 * The number of live task contexts. The pool is bounded, and a full pool
 * fails ops.init_task() with -ENOMEM.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} task_count_stor SEC(".maps");

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
 * One group entity of the tree.
 *
 * The node is at offset 0, so a queue that holds group entities returns
 * the entity pointer from the node. The children queue holds the direct
 * tasks of the cgroup and the child group entities of the same cgroup.
 *
 * v_q16 is the service of this entity on the scale of its parent queue.
 * frontier_q16 is the monotone frontier of the children queue. count is
 * the number of dispatchable children. tie is the insertion record of
 * this entity in its parent queue, and tie_seq is the counter of that
 * queue.
 */
struct inf_group_entity {
	struct scx_edq_task qnode;
	struct scx_edq children;
	u64 v_q16;
	u64 rem;
	u64 frontier_q16;
	u64 cgrp_id;
	u64 count;
	u64 tie;
	u64 tie_seq;
	u64 epoch;
	u32 parent_idx;
	u32 weight;
	u32 gate_seq;
	u32 class;
	u16 nr_children;
	u16 flags;
	u32 state;
	u32 pad;
};

typedef struct inf_group_entity __arena inf_group_entity_t;

/*
 * The candidate of a band scan. The node is held while the scan runs and
 * the winner keeps its hold until the caller removes it.
 */
struct inf_cand {
	scx_edq_task_t *task;
	u64		 v;
	u64		 tie;
	u32		 cls;
	bool		 valid;
};

/*
 * One slot of the open-addressed index that maps a cgroup id to the
 * entity index of that cgroup on this CPU. A deleted slot keeps a
 * tombstone so the probe chain stays intact.
 */
struct inf_index_slot {
	u64 cgrp_id;
	u32 ent_idx;
	u32 state; /* 0 empty, 1 used, 2 tombstone */
};

typedef struct inf_index_slot __arena inf_index_slot_t;
typedef u8 __arena inf_byte_t;

/*
 * The entity store of one CPU: the group entities, the cgroup index and
 * the occupancy bitmap of the entity slots. Slot 0 of the entity array is
 * the root entity and always exists.
 */
struct inf_cpu_block {
	struct inf_group_entity ents[INF_GROUPS_PER_CPU];
	struct inf_index_slot index[INF_INDEX_SLOTS];
	/*
	 * The scan cursor of the band scan. It lives in the arena because
	 * the queue API takes an arena pointer, and a BPF stack slot
	 * cannot hold an arena object.
	 */
	struct scx_edq_cursor cursor;
	/* The occupancy bitmap of the entity slots, one bit per slot. */
	u8 bitmap[INF_GROUPS_PER_CPU / 8];
	/* The free entity slots, as a stack of released indices. */
	u16 free_slots[INF_GROUPS_PER_CPU];
	u16 nr_free;
	u16 nr_used;
	/*
	 * The counters of the scans. A counter that lives in the arena is
	 * an imprecise value for the verifier, so the states of a scan stay
	 * equal and the verifier explores the scan once instead of once per
	 * step.
	 */
	u32 counter[INF_MAX_COUNTERS];
	/*
	 * The path of a selection. The scratch lives in the arena, so the
	 * path arrays have no static bound for the verifier to check.
	 */
	struct inf_path path;
	/*
	 * The winner of a band scan. The scan reports it through the
	 * scratch, so its return value carries no pointer and the caller
	 * does not multiply its states.
	 */
	struct inf_cand win;
};

typedef struct inf_cpu_block __arena inf_cpu_block_t;

#define INF_IDX_NONE 0xffffffffU

/*
 * Per-task context, allocated in the arena by scx_task_alloc(). The
 * bandwidth context must stay first: REGISTER_SCX_CGROUP_BW_ENQUEUE_CB()
 * and the scx_cgroup_bw_* API cast the context to scx_task_common at offset
 * 0. The queue node follows it and is embedded for the task's whole
 * lifetime.
 */
struct task_ctx {
	struct scx_task_cgroup_bw cg_bw; /* MUST be first */
	struct scx_edq_task qnode;	 /* link in the parent group queue */
	u64 v_q16;			 /* service on the parent scale */
	u64 rem;			 /* retained division remainder */
	u64 tie;			 /* insertion counter in the parent */
	u64 latched_weight;		 /* weight of the next charge */
	u64 epoch;			 /* epoch of the latched weight */
	u64 parent_idx;		 /* the leaf parent entity */
	u64 cgrp_id;			 /* the cgroup of the leaf parent */
	u64 slice_ns;			 /* the last assigned slice */
	u64 last_running_ns;		 /* clock at the last ops.running() */
	u64 base_weight;			 /* p->scx.weight at the last change */
	u32 path_ent[INF_MAX_LEVELS];	 /* the held path, leaf parent first */
	s32 queued_cpu;			 /* the CPU whose tree holds the task */
	s32 path_cpu;			 /* the CPU whose tree holds the path */
	u32 path_depth;			 /* the number of group levels */
	u32 state;				 /* enum inf_entity_state */
	u32 class;				 /* the insertion class */
	u32 moving;				 /* one writer owns a queue move */
	u32 dequeue_pending;			 /* a dequeue arrived during a move */
	u32 exit_pending;			 /* an exit arrived during a move */
	u32 reweight_pending;			 /* apply the new weight at the next step */
	u32 joined;				 /* the cgroup counts this task */
	u32 yielded;				 /* the task asked to yield */
	u32 preempted;			 /* the task lost its slice to a preemption */
	u32 wake_fork;			 /* the wakeup carried SCX_WAKE_FORK */
	u32 idle;				 /* the task sits under an idle group */
	u32 pid;
	u32 pending_event;			 /* the event of the ending slot */
	u32 hist_idx;
	struct inf_hist hist[8];
};

typedef struct task_ctx __arena task_ctx;

/* The reservation flags. */
#define INF_RESV_RUNNING 1U

/* The entity store. One block per possible CPU, never resized. */
static inf_cpu_block_t *inf_blocks;
static u32		inf_nr_blocks;

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
_Static_assert(sizeof(struct scx_edq_task) == INF_QUEUE_NODE_BYTES,
	       "EDQ node does not match INF_QUEUE_NODE_BYTES");

static __always_inline task_ctx *inf_task_ctx(struct task_struct *p)
{
	return (task_ctx *)__scx_task_data(p);
}

/* Apply the pending dequeue or exit of a task whose move was interrupted. */
static __noinline void inf_resolve_pending(task_ctx *tctx);

/*
 * True when the node belongs to the entity array of a block. The children
 * queue of a group holds both group entities and task nodes, so the caller
 * needs to know which one it holds.
 */
static __always_inline bool inf_node_is_group(inf_cpu_block_t *blk, u64 node)
{
	u64 base = (u64)&blk->ents[0];
	u64 end  = base + (u64)sizeof(blk->ents);

	return node >= base && node < end;
}

static __always_inline task_ctx *inf_task_ctx_alloc(struct task_struct *p)
{
	return (task_ctx *)scx_task_alloc(p);
}

/*
 * Recover the task context from the queue node embedded in it.
 *
 * A queue returns the node, not the object that owns it. For a group entity
 * the node is at offset 0, so the two pointers are equal and the entity
 * pointer is already the answer. For a task the node sits at
 * offsetof(struct task_ctx, qnode), and every caller that receives a node
 * from a queue must subtract that offset before it reads a task field.
 */
static __always_inline task_ctx *
inf_task_from_qnode(scx_edq_task_t *node)
{
	return (task_ctx *)(void __arena *)((u64)node -
					    offsetof(struct task_ctx, qnode));
}

/* The entity block of one CPU. */
static __always_inline inf_cpu_block_t *inf_block(s32 cpu)
{
	if (cpu < 0 || (u32)cpu >= inf_nr_blocks)
		return NULL;
	return &inf_blocks[cpu];
}

/* The group entity at @idx. */
static __always_inline inf_group_entity_t *inf_entity(inf_cpu_block_t *blk,
						      u32 idx)
{
	if (idx >= INF_GROUPS_PER_CPU)
		return NULL;
	return &blk->ents[idx];
}

/* The index of an entity inside its block. */
static __always_inline u32 inf_entity_index(inf_cpu_block_t *blk,
					     inf_group_entity_t *e)
{
	return (u32)(e - &blk->ents[0]);
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
			rec->group_cpu = tctx->queued_cpu;
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

		bpf_for(i, 0, 8)
		{
			u32 slot = (tctx->hist_idx - snap->hist_count + i) & 7;

			snap->hist[i] = tctx->hist[slot];
		}
	}

	snap->ts	       = bpf_ktime_get_ns();
	snap->slice	       = tctx->slice_ns;
	snap->weight	       = tctx->latched_weight;
	snap->pid	       = tctx->pid;
	snap->queued_cpu       = tctx->queued_cpu;
	snap->group_cpu	       = tctx->path_cpu;
	snap->state	       = tctx->state;
	snap->hold	       = inf_queue_node_hold(&tctx->qnode);
	snap->joined	       = tctx->joined;
	snap->moving	       = tctx->moving;
	snap->reweight_pending = tctx->reweight_pending;
	snap->dequeue_pending  = tctx->dequeue_pending;
	snap->exit_pending     = tctx->exit_pending;
	snap->last_op	       = op;
	snap->last_src	       = src;
	snap->last_dst	       = dst;
	snap->last_result      = result;

	if (bpf_map_update_elem(&tsnap_stor, &pid, snap, BPF_ANY))
		__sync_fetch_and_add(&ctl->task_overflow, 1);
}

/*
 * Exit-time snapshot of every per-CPU tree. The head pointer is read
 * without the queue lock: a diagnostic record may be stale, and taking a
 * queue lock in the exit path risks a second error.
 */
static __noinline void inf_dump_queues(void)
{
	u32 ncpu = inf_nr_blocks;
	u32 cpu;

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		struct inf_queue_snap *qs;
		struct inf_cpu_ctx    *cctx;
		inf_cpu_block_t	      *blk;
		inf_group_entity_t    *root;
		scx_edq_task_t   *head;
		task_ctx	      *tctx;

		if (cpu >= ncpu)
			break;

		qs = bpf_map_lookup_elem(&qsnap_stor, &cpu);
		if (!qs)
			continue;

		blk = inf_block((s32)cpu);
		cctx = inf_cpu_ctx((s32)cpu);
		if (!blk || !cctx)
			continue;

		__builtin_memset(qs, 0, sizeof(*qs));
		qs->cpu	  = (s32)cpu;
		qs->depth = READ_ONCE(cctx->depth);

		root = inf_entity(blk, 0);
		if (!root)
			continue;

		head = (scx_edq_task_t *)root->children.first;
		if (!head)
			continue;

		if (inf_node_is_group(blk, (u64)head)) {
			inf_group_entity_t *e = (inf_group_entity_t *)head;

			qs->head_pid	 = 0;
			qs->head_weight = e->weight;
			qs->head_key	 = e->v_q16;
			qs->head_state	 = e->state;
			qs->head_hold	 = inf_queue_node_hold(head);
			continue;
		}

		tctx		   = inf_task_from_qnode(head);
		qs->head_pid	   = (s32)tctx->pid;
		qs->head_cpu	   = tctx->queued_cpu;
		qs->head_group_cpu = tctx->path_cpu;
		qs->head_state	   = tctx->state;
		qs->head_hold	   = inf_queue_node_hold(head);
		qs->head_slice	   = tctx->slice_ns;
		qs->head_weight	   = tctx->latched_weight;
		qs->head_key	   = tctx->v_q16;
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

static __always_inline u32 inf_nr_cpu_ids(void)
{
	u32 n = nr_cpu_ids;

	if (!n)
		n = scx_bpf_nr_cpu_ids();
	return n;
}

/*
 * The live control state of one cgroup, or NULL when the cgroup has no
 * entry. The entry is the proof that the cgroup is alive: the cgroup
 * callbacks create it and remove it.
 */
static __always_inline struct inf_cgrp_state *inf_cgrp_state(u64 cgrp_id)
{
	return bpf_map_lookup_elem(&cgrp_state_stor, &cgrp_id);
}

/* The weight of a group entity: its cpu.weight, or 3 when it is idle. */
static __always_inline u32 inf_cgroup_weight(u64 cgrp_id, bool *idle)
{
	struct inf_cgrp_state *st = inf_cgrp_state(cgrp_id);
	u32		      w  = INF_WEIGHT_DEFAULT;

	if (st) {
		w = st->weight;
		if (idle)
			*idle = st->idle != 0;
	}
	if (w < INF_WEIGHT_MIN)
		w = INF_WEIGHT_MIN;
	if (w > INF_WEIGHT_MAX)
		w = INF_WEIGHT_MAX;
	if (idle && *idle)
		w = INF_WEIGHT_IDLE;
	return w;
}

/*
 * The task's cgroup, read from the task as the kernel does. A NULL
 * task group or a NULL cgroup means the process root cgroup.
 */
static __always_inline struct cgroup *inf_task_cgroup(struct task_struct *p)
{
	struct task_group *tg;

	if (!bpf_core_field_exists(struct task_struct, sched_task_group))
		return NULL;

	tg = BPF_CORE_READ(p, sched_task_group);
	if (!tg)
		return NULL;

	return BPF_CORE_READ(tg, css.cgroup);
}

/* The control-group id of a cgroup. */
static __always_inline u64 inf_cgroup_id(struct cgroup *cgrp)
{
	return BPF_CORE_READ(cgrp, kn, id);
}

/* The ancestor of @cgrp at @level, or NULL. */
static __always_inline struct cgroup *inf_cgroup_ancestor(struct cgroup *cgrp,
							  int		  level)
{
	if (level < 0 || level > BPF_CORE_READ(cgrp, level))
		return NULL;

	return BPF_CORE_READ(cgrp, ancestors[level]);
}

/*
 * The weight of a task entity: its nice weight, or 3 when the task is a
 * SCHED_IDLE task.
 */
static __always_inline u32 inf_task_weight(struct task_struct *p)
{
	if (p->policy == INF_SCHED_IDLE)
		return INF_WEIGHT_IDLE;
	if (p->scx.weight)
		return p->scx.weight;
	return INF_WEIGHT_DEFAULT;
}

/*
 * The service comparison is wrap-safe. The half-range invariant of the
 * specification keeps every compared pair inside half the range.
 */
static __always_inline bool inf_service_less(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static __always_inline u64 inf_service_max(u64 a, u64 b)
{
	return inf_service_less(a, b) ? b : a;
}

/*
 * Charge @runtime_ns of service at @weight and keep the remainder. The
 * remainder is smaller than the weight and avoids a truncation bias at
 * short runtimes.
 */
static __always_inline u64 inf_charge_service(u64 __arena *v, u64 __arena *rem,
					      u64 runtime_ns, u32 weight)
{
	u64 scaled;
	u64 delta;

	if (!weight)
		weight = 1;
	if (runtime_ns > INF_SETTLE_MAX_NS) {
		runtime_ns = INF_SETTLE_MAX_NS;
		INF_STAT_INC(settle_clamps);
	}
	scaled = runtime_ns * INF_SERVICE_SCALE + *rem;
	delta  = scaled / weight;
	*rem   = scaled % weight;
	*v	    = *v + delta;
	return delta;
}

/*
 * The open-addressed index. The key is the cgroup id, the value the
 * entity index. The maximum load factor is 50 percent, because 128
 * entities fill at most 128 of the 256 slots.
 */
static __always_inline u32 inf_index_start(u64 cgrp_id)
{
	return (u32)((cgrp_id ^ (cgrp_id >> 32)) & (INF_INDEX_SLOTS - 1));
}

/*
 * The probe walks the table with a pointer. A pointer induction variable
 * keeps the verifier states equal, so the probe costs one exploration
 * instead of one per slot.
 */
static __noinline u32 inf_index_find(inf_cpu_block_t *blk, u64 cgrp_id)
{
	inf_index_slot_t *s = &blk->index[inf_index_start(cgrp_id)];
	inf_index_slot_t *end = &blk->index[INF_INDEX_SLOTS];
	inf_index_slot_t *base = &blk->index[0];

	while (can_loop) {
		if (s->state == 0)
			return INF_IDX_NONE;
		if (s->state == 1 && s->cgrp_id == cgrp_id)
			return s->ent_idx;
		s++;
		if (s == end)
			s = base;
	}
	return INF_IDX_NONE;
}

static __noinline int inf_index_insert(inf_cpu_block_t *blk, u64 cgrp_id,
				       u32 ent_idx)
{
	inf_index_slot_t *s = &blk->index[inf_index_start(cgrp_id)];
	inf_index_slot_t *end = &blk->index[INF_INDEX_SLOTS];
	inf_index_slot_t *base = &blk->index[0];
	inf_index_slot_t *tomb = NULL;

	while (can_loop) {
		if (s->state == 0) {
			if (tomb)
				s = tomb;
			s->cgrp_id = cgrp_id;
			s->ent_idx = ent_idx;
			s->state   = 1;
			return 0;
		}
		if (s->state == 2 && !tomb)
			tomb = s;
		if (s->state == 1 && s->cgrp_id == cgrp_id) {
			s->ent_idx = ent_idx;
			return 0;
		}
		s++;
		if (s == end)
			s = base;
	}
	if (tomb) {
		tomb->cgrp_id = cgrp_id;
		tomb->ent_idx = ent_idx;
		tomb->state   = 1;
		return 0;
	}
	return -ENOSPC;
}

static __noinline void inf_index_remove(inf_cpu_block_t *blk, u64 cgrp_id)
{
	inf_index_slot_t *s = &blk->index[inf_index_start(cgrp_id)];
	inf_index_slot_t *end = &blk->index[INF_INDEX_SLOTS];
	inf_index_slot_t *base = &blk->index[0];

	while (can_loop) {
		if (s->state == 0)
			return;
		if (s->state == 1 && s->cgrp_id == cgrp_id) {
			s->state = 2;
			return;
		}
		s++;
		if (s == end)
			s = base;
	}
}

/*
 * Take a free entity slot. The released slots sit on a stack, so the
 * allocation needs no scan. A slot that was never used comes from the
 * high water mark. Slot 0 is the root entity and is never free.
 */
static __always_inline int inf_bitmap_alloc(inf_cpu_block_t *blk, u32 *idx)
{
	u32 slot;

	if (blk->nr_free) {
		blk->nr_free--;
		slot = blk->free_slots[blk->nr_free];
	} else if (blk->nr_used < INF_GROUPS_PER_CPU) {
		slot = blk->nr_used;
		blk->nr_used++;
	} else {
		return -ENOSPC;
	}

	blk->bitmap[slot / 8] |= 1 << (slot % 8);
	*idx = slot;
	return 0;
}

static __always_inline void inf_bitmap_free(inf_cpu_block_t *blk, u32 idx)
{
	if (idx == 0 || idx >= INF_GROUPS_PER_CPU)
		return;
	blk->bitmap[idx / 8] &= ~(1 << (idx % 8));
	if (blk->nr_free < INF_GROUPS_PER_CPU) {
		blk->free_slots[blk->nr_free] = (u16)idx;
		blk->nr_free++;
	}
}

/*
 * Create the entity of one cgroup on this CPU. The entity starts with
 * the frontier of its parent, so a new entity never sits below the
 * parent's frontier.
 */
static __noinline u32 inf_entity_create(inf_cpu_block_t *blk, u64 cgrp_id,
					 u32 parent_idx, u32 weight)
{
	inf_group_entity_t *e;
	u32			idx;

	if (inf_bitmap_alloc(blk, &idx)) {
		INF_STAT_INC(entity_alloc_fail);
		return INF_IDX_NONE;
	}

	e = inf_entity(blk, idx);
	if (!e) {
		inf_bitmap_free(blk, idx);
		return INF_IDX_NONE;
	}

	e->v_q16	= 0;
	e->rem		= 0;
	/*
	 * The children queue of a new entity is empty, so its frontier
	 * starts at zero. The entity itself takes the frontier of its
	 * parent when it enters the parent queue.
	 */
	e->frontier_q16 = 0;
	e->cgrp_id	= cgrp_id;
	e->count	= 0;
	e->tie		= 0;
	e->tie_seq	= 0;
	e->epoch	= scx_cgroup_ctl_epoch();
	e->parent_idx	= parent_idx;
	e->weight	= weight;
	e->gate_seq	= 0;
	e->class	= INF_CLASS_HEAD;
	e->nr_children	= 0;
	e->flags	= 0;
	e->state	= INF_ENTITY_INACTIVE;

	inf_queue_init(&e->children);
	inf_queue_node_init(&e->qnode);

	if (inf_index_insert(blk, cgrp_id, idx)) {
		inf_bitmap_free(blk, idx);
		INF_STAT_INC(entity_alloc_fail);
		return INF_IDX_NONE;
	}

	return idx;
}

/* Release one entity slot. The entity must not hold a running path. */
static __noinline void inf_entity_release(inf_cpu_block_t *blk, u32 idx)
{
	inf_group_entity_t *e = inf_entity(blk, idx);

	if (!e)
		return;

	if (e->state == INF_ENTITY_SELECTED || e->state == INF_ENTITY_RUNNING) {
		/*
		 * A running path holds the entity. The cgroup is gone, so
		 * the entity stays dead and the path releases it when it
		 * re-enters the tree.
		 */
		e->state = INF_ENTITY_EXITING;
		return;
	}

	if (e->state == INF_ENTITY_RUNNABLE) {
		inf_group_entity_t *par = inf_entity(blk, e->parent_idx);

		if (par)
			inf_queue_remove(&par->children, &e->qnode);
	}

	inf_index_remove(blk, e->cgrp_id);
	inf_bitmap_free(blk, idx);
	e->state	= INF_ENTITY_EXITING;
	e->count	= 0;
	e->cgrp_id	= 0;
	INF_STAT_INC(entity_reclaims);
}

/*
 * The entity of one cgroup on this CPU, or INF_IDX_NONE. A cgroup that
 * has exited has no live entry, so its entity is stale and the slot is
 * reclaimed here.
 */
static __noinline u32 inf_lookup_entity(inf_cpu_block_t *blk, u64 cgrp_id)
{
	u32 idx = inf_index_find(blk, cgrp_id);

	if (idx == INF_IDX_NONE)
		return INF_IDX_NONE;

	if (!inf_cgrp_state(cgrp_id)) {
		inf_entity_release(blk, idx);
		return INF_IDX_NONE;
	}

	return idx;
}

/*
 * Find or create the entity of every cgroup between the task's cgroup and
 * the root, and return the entity that holds the task. The walk starts at
 * the top of the chain, so a parent entity exists before its child.
 *
 * A full group pool falls back to the nearest ancestor that has an
 * entity, or to the root entity. The task stays runnable and the overflow
 * is counted.
 */
static __noinline u32 inf_resolve_leaf(inf_cpu_block_t *blk, struct cgroup *cgrp,
					u64 *cgrp_id_out)
{
	u32	parent = 0;
	int	level;
	int	i;

	*cgrp_id_out = 0;
	if (!cgrp)
		return 0;

	level = BPF_CORE_READ(cgrp, level);
	if (level > INF_MAX_LEVELS)
		level = INF_MAX_LEVELS;

	for (i = 1; i <= INF_CHAIN_MAX && can_loop; i++) {
		struct cgroup *anc;
		u64		id;
		u32		idx;

		if (i > level)
			break;
		anc = inf_cgroup_ancestor(cgrp, i);
		if (!anc)
			break;

		id = inf_cgroup_id(anc);
		idx = inf_lookup_entity(blk, id);
		if (idx == INF_IDX_NONE) {
			idx = inf_entity_create(blk, id, parent,
						inf_cgroup_weight(id, NULL));
			if (idx == INF_IDX_NONE) {
				/*
				 * The pool is full. The task joins the
				 * nearest ancestor that has an entity.
				 */
				INF_STAT_INC(entity_overflow);
				break;
			}
		}
		parent = idx;
	}

	*cgrp_id_out = inf_cgroup_id(cgrp);
	return parent;
}

/*
 * The insertion class of a child in a parent queue. A normal insertion
 * takes one gate step, and the gate decides the head or the tail. In every
 * eight normal insertions, one takes the tail.
 */
static __always_inline u32 inf_gate_class(inf_group_entity_t *parent, u32 mode)
{
	u32 seq;

	if (mode == INF_INS_TAIL)
		return INF_CLASS_TAIL;
	if (mode == INF_INS_HEAD)
		return INF_CLASS_HEAD;

	seq = parent->gate_seq++;
	if ((seq & INF_GATE_MASK) == INF_GATE_MASK)
		return INF_CLASS_TAIL;
	return INF_CLASS_HEAD;
}

/* Insert a group entity into the queue of its parent. */
static __always_inline void inf_link_entity(inf_cpu_block_t *blk,
					     inf_group_entity_t *e, u32 mode)
{
	inf_group_entity_t *par = inf_entity(blk, e->parent_idx);

	if (!par)
		return;

	e->v_q16 = inf_service_max(e->v_q16, par->frontier_q16);
	e->class = inf_gate_class(par, mode);
	e->tie   = par->tie_seq++;
	inf_queue_insert(&par->children, &e->qnode, e->v_q16);
	e->state = INF_ENTITY_RUNNABLE;
}

/*
 * A new dispatchable child of @idx. The entity and its dormant ancestors
 * enter their parent queues. The walk is bounded by the maximum number of
 * tree levels.
 */
static __noinline void inf_count_up(inf_cpu_block_t *blk, u32 idx, u32 mode)
{
	u32 i;

	for (i = 0; i < INF_MAX_LEVELS && idx != 0 && can_loop; i++) {
		inf_group_entity_t *e = inf_entity(blk, idx);
		bool			dormant;

		if (!e)
			return;
		dormant = e->count == 0;
		e->count++;
		if (!dormant)
			return;
		inf_link_entity(blk, e, mode);
		idx = e->parent_idx;
	}
}

/*
 * One dispatchable child of @idx left. The entity and its dormant
 * ancestors leave their parent queues and keep their history. The walk is
 * bounded by the maximum number of tree levels.
 */
static __noinline void inf_count_down(inf_cpu_block_t *blk, u32 idx)
{
	u32 i;

	for (i = 0; i < INF_MAX_LEVELS && idx != 0 && can_loop; i++) {
		inf_group_entity_t *e = inf_entity(blk, idx);

		if (!e)
			return;
		if (e->count > 0)
			e->count--;
		if (e->count > 0)
			return;
		if (e->state == INF_ENTITY_RUNNABLE) {
			inf_group_entity_t *par = inf_entity(blk, e->parent_idx);

			if (par)
				inf_queue_remove(&par->children, &e->qnode);
			e->state = INF_ENTITY_INACTIVE;
		}
		idx = e->parent_idx;
	}
}

/*
 * The service value, the insertion class and the tie of a queued child.
 */
static __always_inline void inf_node_info(inf_cpu_block_t *blk, u64 node,
					  u64 *v, u32 *cls, u64 *tie)
{
	if (inf_node_is_group(blk, node)) {
		inf_group_entity_t *e = (inf_group_entity_t *)node;

		*v   = e->v_q16;
		*cls = e->class;
		*tie = e->tie;
	} else {
		task_ctx *t = inf_task_from_qnode((scx_edq_task_t *)node);

		*v   = t->v_q16;
		*cls = t->class;
		*tie = t->tie;
	}
}

/*
 * The order of the children of a queue.
 *
 * A lower service value wins. At equal service the head class wins, and
 * at equal service and class the newest head or the oldest tail wins. The
 * comparison is written without a branch, so the verifier does not branch
 * on the data of the queue and the scan costs one exploration.
 */
static __always_inline u64 inf_band_better(u64 v, u32 cls, u64 tie,
					    u64 best_v, u32 best_cls, u64 best_tie)
{
	u64 c = cls;
	u64 b = best_cls;
	u64 diff = v - best_v;
	u64 lt = (diff >> 63) & 1;
	u64 gt = ((best_v - v) >> 63) & 1;
	u64 eq = 1 - lt - gt;
	u64 n_head = 1 - ((c | (0 - c)) >> 63);
	u64 b_head = 1 - ((b | (0 - b)) >> 63);
	u64 head_wins = n_head & (1 - b_head);
	u64 same = 1 - (n_head ^ b_head);
	u64 tie_newer = ((best_tie - tie) >> 63) & 1;
	u64 tie_better = same & ((tie_newer & n_head) |
				 ((1 - tie_newer) & (1 - n_head)));

	return lt | (eq & (head_wins | tie_better));
}

/* True when @v is inside the band of a queue with minimum @vmin. */
static __always_inline u64 inf_in_band_mask(u64 v, u64 vmin)
{
	u64 cutoff = vmin + INF_BAND_Q16;

	return 1 - (((cutoff - v) >> 63) & 1);
}

/*
 * Scan the eligible prefix of a parent queue and pick the winner.
 *
 * The scan holds the queue lock, so the tree is stable and no task
 * context can be freed while the scan runs. It takes no hold on the
 * children it inspects and takes one hold on the winner before it
 * releases the lock.
 *
 * The scan is bounded. A band that holds more children than the bound
 * falls back to the queue head and counts the truncation.
 */
static __noinline int inf_band_scan(inf_cpu_block_t *blk, scx_edq_t *queue,
				     inf_cpu_block_t *scratch, u64 frontier,
				     u64 *vmin_out, bool *truncated)
{
	struct inf_cand __arena *win = &scratch->win;
	scx_edq_node_t *n;
	scx_edq_task_t *best = NULL;
	u64		 best_v = 0;
	u64		 best_tie = 0;
	u32		 best_cls = 0;
	u64		 vmin = 0;
	u32		 scanned = 0;
	bool		 have = false;
	int		 ret = 0;

	*truncated = false;
	win->valid = false;

	if (inf_queue_lock(queue))
		return -EBUSY;

	n = queue->first;
	scratch->counter[INF_COUNTER_BAND] = 0;
	while (n && can_loop) {
		scx_edq_task_t *task = inf_queue_node_task(n);
		u64		 v, tie, inb, take, mask, first;
		u32		 cls;

		/*
		 * The scan counter lives in the arena, so the verifier sees
		 * an imprecise value and the states of the scan stay equal.
		 */
		if (scratch->counter[INF_COUNTER_BAND] >= INF_BAND_SCAN_MAX)
			break;
		scratch->counter[INF_COUNTER_BAND]++;

		inf_node_info(blk, (u64)task, &v, &cls, &tie);

		first = have ? 0 : 1;

		if (!have) {
			vmin	 = v;
			have = true;
			/*
			 * The minimum must not sit behind the frontier by
			 * more than the band and one settlement. A larger
			 * gap breaks the wrap-safe comparison.
			 */
			if (inf_service_less(vmin, frontier) &&
			    frontier - vmin > INF_BAND_Q16 + INF_SETTLE_MAX_Q16)
				INF_STAT_INC(half_range_faults);
		}

		inb = inf_in_band_mask(v, vmin);
		take = (inf_band_better(v, cls, tie, best_v, best_cls, best_tie) |
			first) &
		       inb;
		mask = 0 - take;

		best_v   = (best_v & ~mask) | (v & mask);
		best_tie = (best_tie & ~mask) | (tie & mask);
		best_cls = (best_cls & ~mask) | (cls & mask);
		best	  = (scx_edq_task_t *)(((u64)best & ~mask) |
					      ((u64)task & mask));

		n = inf_queue_next(n);
	}

	if (best) {
		/*
		 * The hold keeps the winner alive across the gap between
		 * the lock and the removal of the child.
		 */
		scx_edq_task_hold(best);
	} else {
		ret = -ENOENT;
	}

	scanned = scratch->counter[INF_COUNTER_BAND];

	if (scanned >= INF_BAND_SCAN_MAX) {
		/* The next child decides whether the band is wider. */
		scx_edq_node_t *next = inf_queue_next(n);

		if (next) {
			scx_edq_task_t *nt = inf_queue_node_task(next);
			u64		 nv, ntie;
			u32		 ncls;

			inf_node_info(blk, (u64)nt, &nv, &ncls, &ntie);
			if (inf_in_band_mask(nv, vmin)) {
				*truncated = true;
				INF_STAT_INC(band_scan_truncated);
			}
		}
	}

	inf_queue_unlock(queue);

	if (best) {
		win->valid = true;
		win->task  = best;
		win->v	  = best_v;
		win->tie  = best_tie;
		win->cls  = best_cls;
	}

	*vmin_out = vmin;
	return ret;
}

/*
 * Descend from the root of the tree and return the leaf task and the path
 * that holds it. The scan changes no key, no gate, no service and no
 * frontier. The caller applies the frontier when it commits the
 * selection.
 */
static __noinline bool inf_select_leaf(inf_cpu_block_t *blk,
				       inf_cpu_block_t *scratch,
				       task_ctx **leaf)
{
	struct inf_path __arena *path = &scratch->path;
	u32	attempt;
	u32	depth = 0;
	u32	parent = 0;
	bool	restart = false;
	int	ret;

	for (attempt = 0; attempt < 4; attempt++) {
		restart = false;
		parent  = 0;
		depth   = 0;

		/*
		 * The depth is the loop counter, so the verifier sees the
		 * bound of the path arrays.
		 */
		for (depth = 0; depth < INF_MAX_LEVELS && can_loop; depth++) {
			inf_group_entity_t *pe = inf_entity(blk, parent);
			struct inf_cand win;
			u64		vmin = 0;
			bool		trunc = false;

			if (!pe)
				return false;

			ret = inf_band_scan(blk, &pe->children, scratch,
					    pe->frontier_q16, &vmin, &trunc);
			if (ret) {
				/*
				 * A group entity that sits in its parent queue
				 * with no dispatchable child is stale. It cannot
				 * hold the selection, so it leaves the queue and
				 * the selection starts again. The root is never
				 * stale: an empty root is an empty tree.
				 */
				if (ret == -ENOENT && depth > 0) {
					inf_group_entity_t *par =
						inf_entity(blk, pe->parent_idx);

					if (par)
						inf_queue_remove(&par->children,
								 &pe->qnode);
					pe->state = INF_ENTITY_INACTIVE;
					pe->count = 0;
					INF_STAT_INC(state_repairs);
					restart = true;
					break;
				}
				return false;
			}
			win = scratch->win;

			path->vmin[depth] = vmin;

			if (inf_node_is_group(blk, (u64)win.task)) {
				inf_group_entity_t *e =
					(inf_group_entity_t *)win.task;

				if (e->count == 0) {
					/*
					 * A group without a dispatchable
					 * descendant is stale. Remove it and
					 * start the selection again.
					 */
					inf_group_entity_t *par =
						inf_entity(blk, e->parent_idx);

					if (par)
						inf_queue_remove(&par->children,
								 &e->qnode);
					e->state = INF_ENTITY_INACTIVE;
					INF_STAT_INC(state_repairs);
					inf_queue_drop(win.task);
					restart = true;
					break;
				}

				path->ent[depth] = inf_entity_index(blk, e);
				parent = path->ent[depth];
				inf_queue_drop(win.task);
				continue;
			}

			/* The winner is a task: the leaf of the path. */
			path->depth = depth;
			*leaf	  = inf_task_from_qnode(win.task);
			inf_queue_drop(win.task);
			return true;
		}

		if (!restart)
			return false;
	}

	return false;
}

/*
 * The service minimum of every level of a path becomes the frontier of
 * the queue at that level. The frontier never decreases.
 */
static __always_inline void inf_apply_frontier(inf_cpu_block_t *blk,
						struct inf_path __arena *path)
{
	u32 i;

	for (i = 0; i < path->depth && i < INF_MAX_LEVELS; i++) {
		inf_group_entity_t *par =
			inf_entity(blk, i == 0 ? 0 :
				   path->ent[(i - 1) & (INF_MAX_LEVELS - 1)]);

		if (!par)
			continue;
		par->frontier_q16 = inf_service_max(
			par->frontier_q16,
			path->vmin[i & (INF_MAX_LEVELS - 1)]);
	}
}

/*
 * The advisory depth of a tree. It counts the runnable tasks of the tree
 * and steers the placement scan only.
 */
static __always_inline void inf_depth_add(s32 cpu, s64 delta)
{
	struct inf_cpu_ctx *cctx = inf_cpu_ctx(cpu);

	if (!cctx)
		return;
	__sync_fetch_and_add(&cctx->depth, delta);
}

/*
 * Put a task into the tree. The leaf parent is the entity of the task's
 * cgroup on this CPU.
 */
static __noinline void inf_admit_task(inf_cpu_block_t *blk, task_ctx *tctx,
				      u32 leaf_parent, u32 mode)
{
	inf_group_entity_t *parent = inf_entity(blk, leaf_parent);

	if (!parent)
		return;

	tctx->v_q16 = inf_service_max(tctx->v_q16, parent->frontier_q16);
	tctx->class = inf_gate_class(parent, mode);
	tctx->tie   = parent->tie_seq++;
	if (inf_queue_insert(&parent->children, &tctx->qnode, tctx->v_q16)) {
		/*
		 * The node is still linked in another queue. A stale
		 * membership would leave the task invisible to the tree,
		 * so the node is unlinked and the insert is retried.
		 */
		if (inf_queue_unlink(&tctx->qnode)) {
			INF_STAT_INC(lost_state_errors);
			return;
		}
		if (inf_queue_insert(&parent->children, &tctx->qnode,
				     tctx->v_q16)) {
			INF_STAT_INC(lost_state_errors);
			return;
		}
		INF_STAT_INC(state_repairs);
	}
	tctx->state = INF_ENTITY_RUNNABLE;
	inf_count_up(blk, leaf_parent, mode);
	inf_depth_add(tctx->queued_cpu, 1);
}

/*
 * Re-key the ancestors of a held path. Their service value advanced while
 * the task ran, so the queue has to learn the new value. With
 * @new_record the entity takes a new insertion class and tie, which is
 * what the event table calls a replaced key.
 */
static __noinline void inf_rekey_ancestors(task_ctx *tctx, bool new_record,
					    u32 mode)
{
	inf_cpu_block_t	 *blk = inf_block(tctx->path_cpu);
	inf_group_entity_t *e;
	u32			i;

	if (!blk)
		return;

	for (i = 0; i < INF_MAX_LEVELS && can_loop; i++) {
		inf_group_entity_t *par;

		if (i >= tctx->path_depth)
			break;
		e = inf_entity(blk, tctx->path_ent[i]);
		if (!e)
			continue;
		if (e->state != INF_ENTITY_RUNNABLE)
			continue;

		par = inf_entity(blk, e->parent_idx);
		if (!par)
			continue;

		inf_queue_remove(&par->children, &e->qnode);
		if (new_record) {
			e->class = inf_gate_class(par, mode);
			e->tie   = par->tie_seq++;
		}
		inf_queue_insert(&par->children, &e->qnode, e->v_q16);
	}
}

/*
 * The path of a task re-enters the tree. The leaf task and every ancestor
 * on the path take their own insertion class in their own parent queue.
 */
static __noinline void inf_requeue_path(task_ctx *tctx, u32 mode)
{
	inf_cpu_block_t	 *blk = inf_block(tctx->path_cpu);
	inf_group_entity_t *leaf;

	if (!blk)
		return;

	leaf = inf_entity(blk, (u32)tctx->parent_idx);
	if (!leaf)
		return;

	inf_rekey_ancestors(tctx, true, mode);

	tctx->v_q16 = inf_service_max(tctx->v_q16, leaf->frontier_q16);
	tctx->class = inf_gate_class(leaf, mode);
	tctx->tie   = leaf->tie_seq++;
	if (inf_queue_insert(&leaf->children, &tctx->qnode, tctx->v_q16)) {
		if (inf_queue_unlink(&tctx->qnode)) {
			INF_STAT_INC(lost_state_errors);
			return;
		}
		if (inf_queue_insert(&leaf->children, &tctx->qnode,
				     tctx->v_q16)) {
			INF_STAT_INC(lost_state_errors);
			return;
		}
		INF_STAT_INC(state_repairs);
	}
	tctx->state	 = INF_ENTITY_RUNNABLE;
	tctx->queued_cpu = tctx->path_cpu;

	inf_count_up(blk, (u32)tctx->parent_idx, mode);
	/*
	 * A dispatch removed the task from the tree and decremented the
	 * depth. The requeue puts it back, so the depth has to follow.
	 */
	inf_depth_add(tctx->queued_cpu, 1);
}

/* Remove a task from the tree and release the counts below it. */
static __noinline void inf_task_leave_tree(task_ctx *tctx)
{
	inf_cpu_block_t	 *blk = inf_block(tctx->queued_cpu);
	inf_group_entity_t *leaf;

	if (!blk)
		return;

	leaf = inf_entity(blk, (u32)tctx->parent_idx);
	if (!leaf)
		return;

	if (inf_queue_remove(&leaf->children, &tctx->qnode)) {
		/*
		 * The node is not in the queue the task belongs to. The
		 * membership is stale, so the node is unlinked from the
		 * queue that holds it. A node that stays linked would be
		 * found by the selection with a task that is no longer in
		 * the tree.
		 */
		inf_queue_unlink(&tctx->qnode);
		INF_STAT_INC(state_repairs);
	}
	inf_depth_add(tctx->queued_cpu, -1);
	tctx->state	 = INF_ENTITY_INACTIVE;
	tctx->queued_cpu = -1;
	inf_count_down(blk, (u32)tctx->parent_idx);
}

/*
 * The task leaves the tree for good. A task that holds a path releases
 * it, and the ancestors keep their service history.
 */
static __noinline void inf_task_leave(task_ctx *tctx)
{
	if (tctx->state == INF_ENTITY_RUNNABLE) {
		inf_task_leave_tree(tctx);
		return;
	}

	if (tctx->state == INF_ENTITY_SELECTED ||
	    tctx->state == INF_ENTITY_RUNNING) {
		/*
		 * The path is held. The task is not in the tree, so only
		 * the deadlines of the ancestors need a refresh.
		 */
		inf_rekey_ancestors(tctx, false, INF_INS_NORMAL);
		tctx->state      = INF_ENTITY_INACTIVE;
		tctx->path_depth = 0;
		tctx->path_cpu   = -1;
	}
}

/*
 * The insertion mode of an event. A normal admission and a post-slot
 * requeue take a gate step. A tail path requeue and a head-exempt
 * insertion do not.
 */
static __always_inline u32 inf_event_mode(u32 event)
{
	switch (event) {
	case INF_EV_ADMIT_HEAD:
	case INF_EV_YIELD_TO:
		return INF_INS_HEAD;
	case INF_EV_EXPIRY:
	case INF_EV_YIELD:
	case INF_EV_PREEMPT:
		return INF_INS_TAIL;
	default:
		return INF_INS_NORMAL;
	}
}

/*
 * Refresh the weight of an entity at an epoch boundary. A running entity
 * settles with its old latched weight and observes the new weight after
 * the settle.
 */
static __always_inline void inf_refresh_weight(inf_group_entity_t *e)
{
	struct inf_cgrp_state *st;
	u64			epoch = scx_cgroup_ctl_epoch();
	u32			w;

	if (e->epoch == epoch)
		return;

	st = inf_cgrp_state(e->cgrp_id);
	if (!st)
		return;

	w = st->weight;
	if (w < INF_WEIGHT_MIN)
		w = INF_WEIGHT_MIN;
	if (w > INF_WEIGHT_MAX)
		w = INF_WEIGHT_MAX;
	if (st->idle)
		w = INF_WEIGHT_IDLE;

	e->weight = w;
	e->rem	= 0;
	e->epoch = epoch;
}

/*
 * Charge the service of a slot to the task and to every ancestor of its
 * path. Every entity uses its own weight. The ancestors learn their new
 * weight after the charge, so a running entity settles with the weight it
 * was latched with.
 */
static __noinline void inf_charge_path(task_ctx *tctx, u64 policy_ns)
{
	inf_cpu_block_t *blk;
	u32		 i;

	if (!policy_ns)
		return;

	inf_charge_service(&tctx->v_q16, &tctx->rem, policy_ns,
			   (u32)tctx->latched_weight);

	blk = inf_block(tctx->path_cpu);
	if (!blk)
		return;

	for (i = 0; i < INF_MAX_LEVELS && can_loop; i++) {
		inf_group_entity_t *e;

		if (i >= tctx->path_depth)
			break;
		e = inf_entity(blk, tctx->path_ent[i]);
		if (!e)
			continue;
		inf_charge_service(&e->v_q16, &e->rem, policy_ns, e->weight);
		inf_refresh_weight(e);
	}
}

/*
 * Settle the reservation of the running task. The settle closes the
 * reservation, so a second settle charges nothing. It charges the service
 * of the path and the actual runtime of the slot.
 */
static __noinline void inf_settle_slot(struct task_struct *p, task_ctx *tctx,
				       u32 event, bool local)
{
	struct inf_cpu_ctx    *cctx = inf_cpu_ctx(tctx->path_cpu);
	struct inf_reservation *r;
	u64			actual = 0;
	u64			policy;

	if (!cctx)
		return;

	r = &cctx->resv;
	if (!r->pid || r->pid != tctx->pid)
		return;

	if (local) {
		if (r->flags & INF_RESV_RUNNING)
			actual = scx_bpf_now() - r->start_now;
	} else {
		/*
		 * A remote tick cannot read the clock of the CPU that runs
		 * the task. It counts one nominal slot instead.
		 */
		actual = INF_SLOT_NS;
		INF_STAT_INC(remote_slots);
	}

	if (actual > INF_SETTLE_MAX_NS) {
		actual = INF_SETTLE_MAX_NS;
		INF_STAT_INC(settle_clamps);
	}

	policy = actual;
	if (event == INF_EV_YIELD && policy < r->slot_ns)
		policy = r->slot_ns;

	r->actual_ns = actual;
	r->policy_ns = policy;
	r->pid	  = 0;
	r->flags	  = 0;

	/* The service of the path advances by the policy charge. */
	inf_charge_path(tctx, policy);

	/* The actual runtime is the only input to cpu.max. */
	if (actual && inf_cpu_bw_enabled())
		scx_cgroup_ctl_consume(p, (u64)tctx, actual);
}

/*
 * The event of the slot that ends now. The tick records the event, so a
 * later enqueue applies the same class.
 */
static __always_inline u32 inf_slot_event(task_ctx *tctx)
{
	if (tctx->pending_event != INF_EV_NONE)
		return tctx->pending_event;
	if (tctx->yielded)
		return INF_EV_YIELD;
	if (tctx->preempted)
		return INF_EV_PREEMPT;
	return INF_EV_EXPIRY;
}

/*
 * True when the task wins its own queue and the queue of every ancestor.
 *
 * The check reads the head of every queue on the path. The head carries
 * the lowest service of the queue, so a candidate with that service and
 * the head class is the winner of the queue under the band: no other head
 * can have a lower service, and no tail can have a lower service either.
 *
 * The read is advisory. The queue lock is not taken, so the check never
 * blocks and never changes a queue. A queue that changes under the read
 * can only make the check refuse a preemption.
 */
static __noinline bool inf_wakee_wins(inf_cpu_block_t *blk, task_ctx *tctx)
{
	scx_edq_task_t *cand = (scx_edq_task_t *)&tctx->qnode;
	u32		 idx = (u32)tctx->parent_idx;
	u32		 level;

	for (level = 0; level < INF_MAX_LEVELS && can_loop; level++) {
		inf_group_entity_t *pe = inf_entity(blk, idx);
		scx_edq_node_t	 *hn;
		scx_edq_task_t	 *head;
		u64		  head_v, cand_v;
		u32		  head_cls, cand_cls;
		u64		  tie;

		if (!pe)
			return false;

		hn = pe->children.first;
		if (!hn)
			return false;
		head = inf_queue_node_task(hn);

		inf_node_info(blk, (u64)head, &head_v, &head_cls, &tie);
		inf_node_info(blk, (u64)cand, &cand_v, &cand_cls, &tie);

		/*
		 * The candidate must be the lowest service of the queue and
		 * must carry the head class.
		 */
		if (head_v != cand_v || cand_cls != INF_CLASS_HEAD)
			return false;

		if (idx == 0)
			return true;
		cand = (scx_edq_task_t *)pe;
		idx = pe->parent_idx;
	}
	return false;
}

/*
 * Preempt only a fresh wakeup that won its path. The reference Infinity
 * 7.2.6-7 policy preempts on the head-arrival condition alone. A task
 * under a cpu.idle cgroup and a SCHED_IDLE task never preempt.
 */
static __always_inline void inf_maybe_preempt(struct task_struct *p, s32 cpu,
					      u64 enq_flags)
{
	inf_cpu_block_t	 *blk;
	struct task_struct *victim;
	struct inf_stats   *stats;
	u64		    reserve;
	task_ctx	   *tctx;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
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

	/*
	 * The wakee must win its own queue and the queue of every
	 * ancestor under the band. The peek is read-only.
	 */
	blk = inf_block(tctx ? tctx->queued_cpu : cpu);
	if (!blk || !tctx)
		return;
	if (!inf_wakee_wins(blk, tctx))
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

	/*
	 * The victim loses its slice. It re-enters the tree through the
	 * partial preemption row, so the flag tells the enqueue which
	 * event ends the slot.
	 */
	{
		task_ctx *vtctx = inf_task_ctx(victim);

		if (vtctx)
			vtctx->preempted = 1;
	}

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
 * Put a task into the tree of @cpu. The leaf parent is the entity of the
 * task's cgroup on that CPU, and the entity is created on the first join.
 */
static __noinline int inf_admit_on_cpu(struct task_struct *p, task_ctx *tctx,
				       s32 cpu, u32 mode)
{
	inf_cpu_block_t	 *blk = inf_block(cpu);
	inf_group_entity_t *leaf;
	struct cgroup	   *cgrp;
	u64		    cgrp_id;
	u32		    leaf_parent;

	if (!blk)
		return -EINVAL;

	cgrp = inf_task_cgroup(p);
	leaf_parent = inf_resolve_leaf(blk, cgrp, &cgrp_id);

	leaf = inf_entity(blk, leaf_parent);
	if (!leaf)
		return -EINVAL;

	tctx->parent_idx	= leaf_parent;
	tctx->cgrp_id		= cgrp_id;
	tctx->queued_cpu	= cpu;
	tctx->path_cpu		= cpu;
	tctx->latched_weight	= inf_task_weight(p);
	tctx->epoch		= scx_cgroup_ctl_epoch();

	inf_admit_task(blk, tctx, leaf_parent, mode);
	return 0;
}

/*
 * Shared enqueue path. @reenq marks a call from the bandwidth callback: the
 * cgroup has just become unthrottled, so the throttle check is skipped.
 */
static __noinline int inf_enqueue_common(struct task_struct *p, u64 enq_flags,
					 bool reenq)
{
	inf_cpu_block_t	 *blk;
	task_ctx	   *tctx;
	u32		    mode;
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

	tctx = inf_task_ctx(p);
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

	/*
	 * An exiting task must not wait in the scheduler queue for a later
	 * dispatch: by then its pid can be gone, bpf_task_from_pid() fails,
	 * and the core keeps the task in custody until the watchdog. Hand it
	 * to the local DSQ now, while the task pointer is valid.
	 */
	if ((p->flags & PF_EXITING) || tctx->state == INF_ENTITY_EXITING) {
		tctx->queued_cpu = -1;
		tctx->state	 = INF_ENTITY_EXITING;
		inf_trace(INF_TR_EXIT_PASS, tctx, INF_TR_WHERE(cpu, cpu), 3);
		if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0))
			INF_STAT_INC(exit_passes);
		else
			INF_STAT_INC(lost_state_errors);
		return 0;
	}

	/*
	 * A task in a throttled cgroup is parked in the bandwidth backlog and
	 * is not on any of our trees.
	 */
	if (inf_cpu_bw_enabled() && !reenq) {
		ret = scx_cgroup_ctl_throttled(p, (u64)tctx);
		if (ret == -EAGAIN) {
			if (!scx_cgroup_ctl_put_aside(p, (u64)tctx, 0)) {
				inf_task_leave(tctx);
				tctx->state = INF_ENTITY_PARKED;
				INF_STAT_INC(cgrp_throttled);
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

	/*
	 * The task holds a path: the slot ended and the path re-enters the
	 * tree. The event was recorded by the tick, or by the yield and the
	 * preemption.
	 */
	if ((tctx->state == INF_ENTITY_SELECTED ||
	     tctx->state == INF_ENTITY_RUNNING) && tctx->path_cpu == cpu) {
		u32 event = inf_slot_event(tctx);
		u32 mode  = inf_event_mode(event);
		bool local = bpf_get_smp_processor_id() == cpu;

		/*
		 * The settle closes the reservation. The tick already
		 * settled the slot, so a second settle charges nothing.
		 */
		inf_settle_slot(p, tctx, event, local);

		inf_requeue_path(tctx, mode);
		tctx->pending_event = INF_EV_NONE;
		tctx->yielded	  = 0;
		tctx->preempted	  = 0;
		if (mode == INF_INS_TAIL)
			INF_STAT_INC(requeue_tail);
		else
			INF_STAT_INC(requeue_normal);
		inf_trace(INF_TR_REQUEUE, tctx, INF_TR_WHERE(tctx->path_cpu, cpu),
			  (s64)event);
		inf_resolve_pending(tctx);
		return 0;
	}

	/*
	 * The task holds a path on another CPU. The old path is released
	 * and the task enters the tree of this CPU.
	 */
	if (tctx->state == INF_ENTITY_SELECTED ||
	    tctx->state == INF_ENTITY_RUNNING)
		inf_task_leave(tctx);

	/*
	 * A stale membership means a previous move did not finish. Remove
	 * the task from wherever it claims to be, so no task is lost and no
	 * entity is charged twice.
	 */
	if (tctx->state == INF_ENTITY_RUNNABLE) {
		inf_task_leave_tree(tctx);
		inf_trace(INF_TR_ENQ_STALE, tctx, INF_TR_WHERE(cpu, cpu), 0);
	}

	/* A fresh runnable admission. */
	blk = inf_block(cpu);
	if (!blk) {
		INF_STAT_INC(enq_no_cctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return 0;
	}

	mode = (enq_flags & SCX_ENQ_HEAD) ? INF_INS_HEAD : INF_INS_NORMAL;

	if (inf_admit_on_cpu(p, tctx, cpu, mode)) {
		INF_STAT_INC(lost_state_errors);
		INF_STAT_INC(enq_admit_fail);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return 0;
	}

	if (mode == INF_INS_HEAD)
		INF_STAT_INC(exempt_inserts);
	else if (tctx->class == INF_CLASS_TAIL)
		INF_STAT_INC(tail_inserts);
	else
		INF_STAT_INC(head_inserts);

	inf_trace(INF_TR_INSERT, tctx, INF_TR_WHERE(-1, cpu),
		  tctx->class == INF_CLASS_TAIL ? 1 : 0);

	if (enq_flags & SCX_ENQ_WAKEUP)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	else if (cpu != bpf_get_smp_processor_id())
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	inf_maybe_preempt(p, cpu, enq_flags);
	return 0;
}

void BPF_STRUCT_OPS(infinity_enqueue, struct task_struct *p, u64 enq_flags)
{
	inf_enqueue_common(p, enq_flags, false);
}

/*
 * Bandwidth callback: a group that throttled @p has time again. Re-enqueue
 * through the normal path so the task re-enters through the gate and
 * rejoins its cgroup.
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
 * Select the leaf task of this CPU's tree and hand it to the local DSQ.
 * The path of the task leaves the tree and is held by the reservation.
 */
static __noinline bool inf_dispatch_tree(s32 cpu, struct inf_cpu_ctx *cctx)
{
	inf_cpu_block_t	 *blk = inf_block(cpu);
	inf_group_entity_t *leaf;
	struct inf_path __arena *path;
	struct task_struct *p;
	task_ctx	   *tctx = NULL;
	u32		    i;
	u32		    leaf_idx;
	int		    ret;

	if (!blk)
		return false;

	path = &blk->path;

	if (!inf_select_leaf(blk, blk, &tctx))
		return false;

	/*
	 * The parent of the selected task is the deepest entity on the
	 * path, not the first one: a task two cgroup levels below the root
	 * sits in the child queue of path->ent[1]. A task that is a direct
	 * child of the root cgroup has no group level on its path, and the
	 * root entity holds it.
	 */
	leaf_idx = path->depth > 0 ?
		   path->ent[(path->depth - 1) & (INF_MAX_LEVELS - 1)] : 0;
	leaf = inf_entity(blk, leaf_idx);
	if (!leaf)
		return false;

	if (tctx->state != INF_ENTITY_RUNNABLE) {
		INF_STAT_INC(disp_stale_state);
		if (tctx->state == INF_ENTITY_INACTIVE)
			INF_STAT_INC(disp_stale_inactive);
		else if (tctx->state == INF_ENTITY_SELECTED)
			INF_STAT_INC(disp_stale_selected);
		else if (tctx->state == INF_ENTITY_RUNNING)
			INF_STAT_INC(disp_stale_running);
	}

	{
		struct inf_stats *st = inf_stats();

		if (st)
			WRITE_ONCE(st->pid_sample, tctx->pid);
	}
	p = bpf_task_from_pid(tctx->pid);
	if (!p) {
		/*
		 * The pid lookup failed, so there is no task pointer to hand
		 * to a DSQ. The core still counts the task as queued: put the
		 * node back and retry on the next dispatch. Dropping it here
		 * stranded a runnable task until the watchdog.
		 */
		INF_STAT_INC(stale_requeues);
		inf_requeue_path(tctx, INF_INS_TAIL);
		inf_queue_drop(&tctx->qnode);
		return false;
	}

	/* The leaf task leaves the queue of its parent. */
	inf_queue_hold(&tctx->qnode);
	ret = inf_queue_remove(&leaf->children, &tctx->qnode);
	if (ret) {
		/*
		 * The node is not in the queue the selection found it in.
		 * The membership is stale, so the node is unlinked from the
		 * queue that holds it and the task is admitted again. The
		 * task stays runnable either way.
		 */
		inf_queue_drop(&tctx->qnode);
		INF_STAT_INC(disp_remove_fail);
		if (ret == -EINVAL)
			INF_STAT_INC(disp_remove_einval);
		inf_trace(INF_TR_REMOVE_FAIL, tctx, INF_TR_WHERE(cpu, -1), ret);
		/*
		 * The node left this queue between the scan and the remove. A
		 * steal, a yield-to or an enqueue on another CPU owns it now,
		 * and the owner keeps the task runnable. The selection is
		 * dropped without touching the node. Only a node with no
		 * membership is repaired here.
		 */
		if (inf_queue_node_owner(&tctx->qnode)) {
			bpf_task_release(p);
			return false;
		}
		inf_queue_unlink(&tctx->qnode);
		INF_STAT_INC(state_repairs);
		if (inf_admit_on_cpu(p, tctx, cpu, INF_INS_NORMAL))
			INF_STAT_INC(lost_state_errors);
		bpf_task_release(p);
		return false;
	}

	tctx->state	 = INF_ENTITY_SELECTED;
	tctx->queued_cpu = -1;
	inf_depth_add(cpu, -1);

	/* The counts below the leaf follow the task. */
	inf_count_down(blk, leaf_idx);

	/* The path of the task is held by the task. */
	tctx->path_depth = path->depth;
	tctx->path_cpu   = cpu;
	if (tctx->path_depth > INF_MAX_LEVELS)
		tctx->path_depth = INF_MAX_LEVELS;
	for (i = 0; i < INF_MAX_LEVELS && can_loop; i++) {
		if (i >= tctx->path_depth)
			break;
		tctx->path_ent[i] = path->ent[i & (INF_MAX_LEVELS - 1)];
	}

	/* The frontier of every level follows the selection. */
	inf_apply_frontier(blk, path);

	if ((p->flags & PF_EXITING) || tctx->state == INF_ENTITY_EXITING) {
		/*
		 * An exiting task in kernel custody is handed to the local
		 * DSQ. The core clears custody and the CPU runs the final
		 * exit.
		 */
		tctx->state	 = INF_ENTITY_EXITING;
		tctx->exit_pending = 0;
		tctx->queued_cpu   = -1;
		tctx->path_depth   = 0;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			INF_STAT_INC(lost_state_errors);
		} else {
			tctx->slice_ns = INF_SLOT_NS;
			if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, INF_SLOT_NS, 0))
				INF_STAT_INC(exit_passes);
			else
				INF_STAT_INC(lost_state_errors);
		}
		bpf_task_release(p);
		inf_queue_drop(&tctx->qnode);
		return false;
	}

	if (tctx->dequeue_pending) {
		tctx->dequeue_pending = 0;
		tctx->state	      = INF_ENTITY_INACTIVE;
		bpf_task_release(p);
		inf_queue_drop(&tctx->qnode);
		INF_STAT_INC(stale_pops);
		inf_trace(INF_TR_POP_PENDING, tctx, INF_TR_WHERE(cpu, -1), 0);
		return false;
	}

	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		s32 target = inf_task_allowed_cpu(p, cpu);

		/*
		 * The task may not run here. It leaves this tree and enters
		 * the tree of a CPU its mask allows.
		 */
		inf_task_leave(tctx);
		if (target >= 0 && !inf_admit_on_cpu(p, tctx, target,
						    INF_INS_NORMAL)) {
			scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
		} else {
			INF_STAT_INC(lost_state_errors);
			INF_STAT_INC(disp_affinity_fail);
		}
		inf_trace(INF_TR_POP_AFFINITY, tctx, INF_TR_WHERE(cpu, target),
			  0);
		bpf_task_release(p);
		inf_queue_drop(&tctx->qnode);
		return false;
	}

	/* The reservation of the slot. */
	cctx->resv.pid	    = tctx->pid;
	cctx->resv.cpu	    = (u32)cpu;
	cctx->resv.slot_ns  = INF_SLOT_NS;
	cctx->resv.start_now = 0;
	cctx->resv.flags    = 0;

	tctx->slice_ns = INF_SLOT_NS;
	tctx->state    = INF_ENTITY_SELECTED;

	INF_STAT_INC(disp_pop);
	INF_STAT_INC(disp_tree);

	if (inject_dsq_refusal) {
		struct inf_test_ctl *tc;
		u32		     tkey = 0;

		tc = bpf_map_lookup_elem(&test_stor, &tkey);
		if (tc && READ_ONCE(tc->dsq_refuse)) {
			__sync_fetch_and_add(&tc->dsq_refuse, -1);
			inf_trace(INF_TR_DSQ_REFUSED, tctx,
				  INF_TR_WHERE(cpu, cpu), 1);
			/* Put the path back with its saved records. */
			cctx->resv.pid = 0;
			inf_requeue_path(tctx, INF_INS_TAIL);
			bpf_task_release(p);
			inf_queue_drop(&tctx->qnode);
			return false;
		}
	}

	if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, INF_SLOT_NS, 0)) {
		/*
		 * The core refused the local insert. Put the path back
		 * instead of dropping a runnable task.
		 */
		inf_trace(INF_TR_DSQ_REFUSED, tctx, INF_TR_WHERE(cpu, cpu), 0);
		INF_STAT_INC(disp_dsq_fail);
		cctx->resv.pid = 0;
		inf_requeue_path(tctx, INF_INS_TAIL);
		bpf_task_release(p);
		inf_queue_drop(&tctx->qnode);
		return false;
	}
	inf_trace(INF_TR_DSQ_OK, tctx, INF_TR_WHERE(cpu, cpu), 0);

	bpf_task_release(p);
	inf_queue_drop(&tctx->qnode);
	return true;
}

/*
 * The read-only peek of a peer tree.
 *
 * The peek follows the head of every queue on the path. The head of a
 * queue is its child with the lowest service, so the peek finds the task
 * the peer would run next. It takes no hold and removes nothing, and it
 * changes no key, no gate, no service and no frontier.
 */
static __noinline bool inf_steal_peek(inf_cpu_block_t *pblk,
				      inf_cpu_block_t *dblk, task_ctx **leaf)
{
	struct inf_path __arena *path = &dblk->path;
	u32	idx = 0;
	u32	level = 0;

	/*
	 * The counter of the peek lives in the arena, so the verifier sees
	 * an imprecise value and the states of the peek stay equal.
	 */
	dblk->counter[INF_COUNTER_PEEK] = 0;
	while (can_loop) {
		inf_group_entity_t *e = inf_entity(pblk, idx);
		scx_edq_node_t	 *hn;
		scx_edq_task_t	 *head;

		if (!e)
			return false;
		hn = e->children.first;
		if (!hn)
			return false;
		head = inf_queue_node_task(hn);

		if (!inf_node_is_group(pblk, (u64)head)) {
			path->depth = level;
			*leaf	  = inf_task_from_qnode(head);
			return true;
		}

		if (dblk->counter[INF_COUNTER_PEEK] >= INF_MAX_LEVELS)
			return false;
		dblk->counter[INF_COUNTER_PEEK]++;
		path->ent[level & (INF_MAX_LEVELS - 1)] = inf_entity_index(
			pblk, (inf_group_entity_t *)head);
		idx = path->ent[level & (INF_MAX_LEVELS - 1)];
		level++;
	}

	return false;
}

/*
 * Steal the leaf task of a peer tree. The peek of the peer tree changes
 * no state. The task leaves the source queue only after the destination
 * accepted the move.
 */
static __noinline bool inf_steal_from(s32 peer, s32 dst,
				      struct inf_cpu_ctx *dcctx)
{
	inf_cpu_block_t	 *pblk = inf_block(peer);
	inf_cpu_block_t	 *dblk = inf_block(dst);
	inf_group_entity_t *sleaf;
	inf_group_entity_t *dleaf;
	struct inf_path __arena *spath = &dblk->path;
	struct task_struct *p;
	task_ctx	   *tctx = NULL;
	u64		    saved_v;
	u32		    saved_cls;
	u64		    saved_tie;
	u64		    saved_parent;
	u64		    saved_cgrp;
	u32		    leaf_parent;
	u32		    sleaf_idx;
	u64		    cgrp_id;
	int		    ret;

	if (!pblk || !dblk)
		return false;

	/*
	 * The hypothetical destination selection: a read-only peek of the
	 * peer tree. The peek reads the head of every queue on the path, so
	 * it costs one read per level and changes no state.
	 */
	if (!inf_steal_peek(pblk, dblk, &tctx))
		return false;

	if (!tctx)
		return false;

	/* The task must be allowed on the destination CPU. */
	{
		struct inf_cpu_topo *dt = inf_cpu_topo(dst);

		if (!dt)
			return false;
	}

	p = bpf_task_from_pid(tctx->pid);
	if (!p) {
		INF_STAT_INC(stale_skips);
		return false;
	}

	if (!inf_cpu_allowed(p, inf_cpu_topo(dst), dst)) {
		bpf_task_release(p);
		return false;
	}

	if (tctx->dequeue_pending || tctx->exit_pending) {
		bpf_task_release(p);
		return false;
	}

	/* One writer owns the move. A lost race is a refusal. */
	inf_queue_hold(&tctx->qnode);
	if (cmpxchg(&tctx->moving, 0, 1)) {
		inf_queue_drop(&tctx->qnode);
		bpf_task_release(p);
		INF_STAT_INC(steal_refusals);
		return false;
	}

	/*
	 * The source leaf. It is the deepest entity on the peer path: the
	 * node sits in the child queue of spath->ent[depth - 1]. A peer
	 * tree whose path has no group level holds the task in the root
	 * entity, so the index is 0.
	 */
	sleaf_idx = spath->depth > 0 ?
		    spath->ent[(spath->depth - 1) & (INF_MAX_LEVELS - 1)] : 0;
	sleaf	  = inf_entity(pblk, sleaf_idx);
	if (!sleaf) {
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		bpf_task_release(p);
		INF_STAT_INC(steal_failures);
		return false;
	}

	/* The source record is saved before the task leaves the source. */
	saved_v		 = tctx->v_q16;
	saved_cls	 = tctx->class;
	saved_tie	 = tctx->tie;
	saved_parent = tctx->parent_idx;
	saved_cgrp	 = tctx->cgrp_id;

	/* The task leaves the source queue. */
	ret = inf_queue_remove(&sleaf->children, &tctx->qnode);
	if (ret) {
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		bpf_task_release(p);
		INF_STAT_INC(steal_failures);
		return false;
	}
	tctx->state	 = INF_ENTITY_HANDOFF;
	tctx->queued_cpu = -1;
	inf_count_down(pblk, sleaf_idx);

	/* The destination leaf parent. */
	leaf_parent = inf_resolve_leaf(dblk, inf_task_cgroup(p), &cgrp_id);
	dleaf	 = inf_entity(dblk, leaf_parent);
	if (!dleaf) {
		goto restore;
	}

	/* The destination frontier, then the normal gate of the leaf. */
	tctx->v_q16 = dleaf->frontier_q16;
	tctx->class = inf_gate_class(dleaf, INF_INS_NORMAL);
	tctx->tie   = dleaf->tie_seq++;
	tctx->parent_idx = leaf_parent;
	tctx->cgrp_id    = cgrp_id;
	tctx->path_cpu   = dst;
	tctx->queued_cpu = dst;

	/* The path of the task on the destination CPU. */
	tctx->path_depth = 0;
	{
		u32 idx = leaf_parent;
		u32 level;

		for (level = 0; level < INF_MAX_LEVELS && idx != 0 && can_loop; level++) {
			inf_group_entity_t *e = inf_entity(dblk, idx);

			if (!e)
				break;
			tctx->path_ent[tctx->path_depth] = idx;
			tctx->path_depth++;
			idx = e->parent_idx;
		}
	}

	ret = inf_queue_insert(&dleaf->children, &tctx->qnode, tctx->v_q16);
	if (ret) {
		INF_STAT_INC(state_repairs);
		goto restore;
	}
	tctx->state = INF_ENTITY_RUNNABLE;
	inf_count_up(dblk, leaf_parent, INF_INS_NORMAL);

	/* The steal committed. */
	tctx->moving = 0;
	INF_STAT_INC(steals);
	INF_STAT_INC(disp_steal);
	inf_trace(INF_TR_STEAL, tctx, INF_TR_WHERE(peer, dst), 0);
	scx_bpf_kick_cpu(dst, SCX_KICK_IDLE);
	inf_queue_drop(&tctx->qnode);
	bpf_task_release(p);
	return true;

restore:
	/*
	 * The destination refused the task. The source record is restored,
	 * so the task keeps its position in the source queue and no gate
	 * advanced.
	 */
	tctx->v_q16  = saved_v;
	tctx->class  = saved_cls;
	tctx->tie    = saved_tie;
	tctx->parent_idx = saved_parent;
	tctx->cgrp_id    = saved_cgrp;
	tctx->state  = INF_ENTITY_RUNNABLE;
	tctx->queued_cpu = peer;
	inf_queue_insert(&sleaf->children, &tctx->qnode, saved_v);
	inf_count_up(pblk, sleaf_idx, INF_INS_NORMAL);
	tctx->moving = 0;
	INF_STAT_INC(steal_failures);
	inf_trace(INF_TR_STEAL_SKIP, tctx, INF_TR_WHERE(peer, dst), -1);
	inf_queue_drop(&tctx->qnode);
	bpf_task_release(p);
	return false;
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
 * Dispatch: the local tree first, then same-LLC peers, then same-NUMA
 * peers outside the local LLC. If nothing is runnable, renew the previous
 * task in place when its slice expired.
 */
void BPF_STRUCT_OPS(infinity_dispatch, s32 cpu, struct task_struct *prev)
{
	struct inf_cpu_ctx  *cctx;
	struct inf_cpu_topo *lt;
	task_ctx	    *tctx = NULL;

	TOUCH_ARENA();

	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	/* Re-enqueue backlogged tasks of cgroups that got time again. */
	if (inf_cpu_bw_enabled())
		scx_cgroup_ctl_reenqueue();

	if (inf_dispatch_tree(cpu, cctx))
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
	 * The tree is empty and the previous task is still runnable with
	 * no slice left. Renew it in place instead of waiting for a round
	 * trip through enqueue.
	 */
	if (prev && !READ_ONCE(prev->scx.slice)) {
		tctx = inf_task_ctx(prev);
		if (tctx)
			scx_bpf_task_set_slice(prev, INF_SLOT_NS);
		INF_STAT_INC(disp_renew);
	}

	inf_trace(INF_TR_DISPATCH_EMPTY, tctx, INF_TR_WHERE(cpu, -1),
		  prev ? 0 : -ENOENT);
}

/*
 * A dequeue or exit arrived while a mover held the task. The mover owns
 * the queue operation, so it applies the pending state before it clears
 * the moving flag.
 */
static __noinline void inf_resolve_pending(task_ctx *tctx)
{
	if (!tctx->dequeue_pending && !tctx->exit_pending)
		return;

	inf_task_leave(tctx);

	if (tctx->exit_pending)
		tctx->state = INF_ENTITY_EXITING;
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
	 * kernel both leave a runnable task that is no longer in BPF custody.
	 */
	core_exec = !!(deq_flags & SCX_DEQ_CORE_SCHED_EXEC);
	ended	  = !core_exec &&
		    (deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_SCHED_CHANGE));

	if (ended) {
		/*
		 * The task leaves the tree. A task that holds a path
		 * releases it, and its ancestors keep their history.
		 */
		if (tctx->moving) {
			tctx->dequeue_pending = 1;
			inf_trace(INF_TR_DEQ_PENDING, tctx,
				  INF_TR_WHERE(tctx->queued_cpu, -1), deq_flags);
			return;
		}
		inf_task_leave(tctx);
		inf_trace(INF_TR_DEQ_QUEUED, tctx,
			  INF_TR_WHERE(tctx->queued_cpu, -1), deq_flags);
	} else {
		inf_trace(INF_TR_DEQ_END, tctx, INF_TR_WHERE(-1, -1), deq_flags);
	}

	/*
	 * SCX_DEQ_CORE_SCHED_EXEC means the core ran a task that was still
	 * queued. It stays runnable, so it moves to RUNNING. A sleep or a
	 * property change ends the runnable period.
	 */
	if (core_exec) {
		tctx->state = INF_ENTITY_RUNNING;
	} else if (ended) {
		if (tctx->state != INF_ENTITY_EXITING)
			tctx->state = INF_ENTITY_INACTIVE;
	}
}

/*
 * The core calls ops.quiescent() when a task leaves the runqueue for any
 * reason. A task that the scheduler already dispatched is no longer in BPF
 * custody, so ops.dequeue() does not run for it: this is the only callback
 * that sees a running task go to sleep. End the runnable period here once.
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

	if (!(deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_SCHED_CHANGE)))
		return;

	if (tctx->state == INF_ENTITY_RUNNABLE ||
	    tctx->state == INF_ENTITY_SELECTED ||
	    tctx->state == INF_ENTITY_RUNNING)
		inf_task_leave(tctx);
}

/*
 * A nice-weight change. The task keeps its service value and re-enters
 * through the normal gate with the new weight.
 */
void BPF_STRUCT_OPS(infinity_set_weight, struct task_struct *p, u32 weight)
{
	task_ctx *tctx;
	s32	    cpu;
	u32	    new_weight;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	INF_STAT_INC(weight_changes);
	inf_trace(INF_TR_SET_WEIGHT, tctx, INF_TR_WHERE(tctx->queued_cpu, -1),
		  (s64)weight);

	new_weight = weight ? weight : INF_WEIGHT_DEFAULT;
	if (new_weight < INF_WEIGHT_MIN)
		new_weight = INF_WEIGHT_MIN;
	if (new_weight > INF_WEIGHT_MAX)
		new_weight = INF_WEIGHT_MAX;
	if (p->policy == INF_SCHED_IDLE)
		new_weight = INF_WEIGHT_IDLE;

	/* The residue is flushed under the old weight. */
	tctx->rem = 0;
	tctx->latched_weight = new_weight;
	tctx->base_weight	  = new_weight;

	if (tctx->state != INF_ENTITY_RUNNABLE)
		return;

	/*
	 * A queued task re-enters through the normal gate. The CPU is read
	 * before the task leaves the tree: the leave clears queued_cpu, and
	 * an admission on CPU -1 has no entity block, so the task would be
	 * dropped from the tree while the core still counts it runnable.
	 */
	cpu = tctx->queued_cpu;
	if (cpu < 0)
		return;

	INF_STAT_INC(reweight_queued);
	INF_STAT_INC(weight_queued_cpu);
	inf_task_leave_tree(tctx);
	if (inf_admit_on_cpu(p, tctx, cpu, INF_INS_NORMAL))
		INF_STAT_INC(lost_state_errors);
	inf_trace(INF_TR_REWEIGHT, tctx, INF_TR_WHERE(cpu, -1), 0);
}

/*
 * Move a runnable queued target to the head of its own queue. The target
 * must be inside its service band. A target that is running, dispatched,
 * throttled, exiting or not queued is refused.
 */
static __noinline bool inf_yield_to(struct task_struct *from,
				    struct task_struct *to)
{
	inf_cpu_block_t	 *blk;
	inf_group_entity_t *parent;
	task_ctx	   *tctx;
	u64		    saved_v;
	u32		    saved_cls;
	u64		    saved_tie;
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
	if (tctx->state != INF_ENTITY_RUNNABLE || tctx->queued_cpu < 0)
		return false;

	tcpu = tctx->queued_cpu;
	/* A task in a sched_ext local DSQ is not in our tree. */
	if (to == __COMPAT_scx_bpf_cpu_curr(tcpu))
		return false;

	blk = inf_block(tcpu);
	if (!blk)
		return false;
	parent = inf_entity(blk, (u32)tctx->parent_idx);
	if (!parent)
		return false;

	/* One writer owns the node. A lost race is a refusal, not a move. */
	inf_queue_hold(&tctx->qnode);
	if (cmpxchg(&tctx->moving, 0, 1)) {
		inf_queue_drop(&tctx->qnode);
		return false;
	}

	saved_v  = tctx->v_q16;
	saved_cls = tctx->class;
	saved_tie = tctx->tie;

	ret = inf_queue_remove(&parent->children, &tctx->qnode);
	if (ret) {
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		INF_STAT_INC(lost_state_errors);
		return false;
	}

	/*
	 * The head class with the newest tie. The gate does not advance, so
	 * the 7:1 ratio of the normal arrivals is unchanged.
	 */
	tctx->class = INF_CLASS_HEAD;
	tctx->tie   = parent->tie_seq++;
	tctx->v_q16 = inf_service_max(tctx->v_q16, parent->frontier_q16);
	if (inf_queue_insert(&parent->children, &tctx->qnode, tctx->v_q16)) {
		/* Put the task back with its saved record. */
		tctx->v_q16  = saved_v;
		tctx->class  = saved_cls;
		tctx->tie    = saved_tie;
		if (inf_queue_insert(&parent->children, &tctx->qnode, saved_v)) {
			tctx->state = INF_ENTITY_INACTIVE;
			tctx->queued_cpu = -1;
			inf_count_up(blk, (u32)tctx->parent_idx, INF_INS_NORMAL);
		}
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		return false;
	}

	inf_count_up(blk, (u32)tctx->parent_idx, INF_INS_NORMAL);
	tctx->moving = 0;
	INF_STAT_INC(yield_to_moves);
	inf_trace(INF_TR_YIELD_TO, tctx, INF_TR_WHERE(tcpu, tcpu), 0);
	inf_queue_drop(&tctx->qnode);
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
	task_ctx	   *tctx;
	struct inf_cpu_ctx *cctx;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_running_ns = scx_bpf_now();
	if (tctx->state == INF_ENTITY_SELECTED)
		tctx->state = INF_ENTITY_RUNNING;

	cctx = inf_cpu_ctx(tctx->path_cpu);
	if (cctx && cctx->resv.pid == tctx->pid) {
		cctx->resv.start_now = tctx->last_running_ns;
		cctx->resv.flags |= INF_RESV_RUNNING;
	}
}

/*
 * The end of a service slot. One ops.tick() call is one slot. The
 * callback settles the reservation, charges the service of the path and
 * ends the slot by zeroing the slice.
 */
void BPF_STRUCT_OPS(infinity_tick, struct task_struct *p)
{
	task_ctx	   *tctx;
	struct inf_cpu_ctx *cctx;
	u32		    event;
	bool		    local;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->state != INF_ENTITY_RUNNING &&
	    tctx->state != INF_ENTITY_SELECTED)
		return;

	cctx = inf_cpu_ctx(tctx->path_cpu);
	if (!cctx || cctx->resv.pid != tctx->pid)
		return;

	/*
	 * A zero slice means the core slice expired before this tick. The
	 * task leaves through the leaf expiry row. A live slice means the
	 * slot ended normally, which is the post-slot ancestor requeue.
	 */
	event = READ_ONCE(p->scx.slice) ? INF_EV_POST_SLOT : INF_EV_EXPIRY;
	tctx->pending_event = event;

	local = bpf_get_smp_processor_id() == (s32)cctx->resv.cpu;

	/*
	 * The settle charges the service of the path and the actual runtime
	 * of the slot. A remote tick counts one nominal slot.
	 */
	inf_settle_slot(p, tctx, event, local);

	INF_STAT_INC(tick_slots);

	/* The slot ends here. The core reschedules the task. */
	scx_bpf_task_set_slice(p, 0);
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
	u64	 *count;
	u32	  key = 0;
	int	  i;

	(void)args;

	TOUCH_ARENA();

	/* The task pool is bounded. A full pool fails the task. */
	count = bpf_map_lookup_elem(&task_count_stor, &key);
	if (count && __sync_fetch_and_add(count, 1) >= INF_TASKS_MAX) {
		__sync_fetch_and_add(count, -1);
		return -ENOMEM;
	}

	tctx = inf_task_ctx_alloc(p);
	if (!tctx) {
		if (count)
			__sync_fetch_and_add(count, -1);
		return -ENOMEM;
	}

	/* Zero the whole context, then seed the live fields. */
	bpf_for(i, 0, (int)sizeof(*tctx))
	{
		((char __arena *)tctx)[i] = 0;
	}

	/* The queue node starts detached with a zero hold count. */
	if (inf_queue_node_init(&tctx->qnode)) {
		scx_task_free_rcu(p);
		if (count)
			__sync_fetch_and_add(count, -1);
		return -EINVAL;
	}

	tctx->base_weight	= p->scx.weight ? p->scx.weight : 1;
	tctx->latched_weight	= inf_task_weight(p);
	tctx->slice_ns		= 0;
	tctx->last_running_ns	= scx_bpf_now();
	tctx->epoch		= scx_cgroup_ctl_epoch();
	tctx->queued_cpu	= -1;
	tctx->path_cpu		= -1;
	tctx->path_depth	= 0;
	tctx->state		= INF_ENTITY_INACTIVE;
	tctx->moving		= 0;
	tctx->reweight_pending	= 0;
	tctx->dequeue_pending	= 0;
	tctx->exit_pending	= 0;
	tctx->joined		= 0;
	tctx->yielded		= 0;
	tctx->preempted		= 0;
	tctx->wake_fork		= 0;
	tctx->idle		= 0;
	tctx->pending_event	= INF_EV_NONE;
	tctx->pid		= p->pid;
	return 0;
}

s32 BPF_STRUCT_OPS(infinity_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	task_ctx *tctx;
	u64	 *count;
	u32	  key = 0;
	int	  ret;

	(void)args;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx) {
		scx_task_free_rcu(p);
		return 0;
	}

	tctx->state = INF_ENTITY_EXITING;

	/* The task leaves the tree, and a held path is released. */
	inf_task_leave(tctx);

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

	count = bpf_map_lookup_elem(&task_count_stor, &key);
	if (count)
		__sync_fetch_and_add(count, -1);

	scx_task_free_rcu(p);
	return 0;
}

void BPF_STRUCT_OPS(infinity_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	task_ctx	   *tctx;
	inf_cpu_block_t   *blk;
	inf_group_entity_t *leaf;
	struct cgroup	   *cgrp;
	u64		    cgrp_id;
	u32		    leaf_parent;
	s32		    cpu;
	int		    ret;

	TOUCH_ARENA();

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	/* The bandwidth library follows the task to the new cgroup. */
	ret = scx_cgroup_ctl_move(p, (u64)tctx, from, to, tctx->path_cpu,
				  tctx->base_weight, false);
	if (ret)
		scx_bpf_error("Failed to move a task between cgroups: %d", ret);

	cpu = tctx->queued_cpu;
	if (cpu < 0)
		cpu = scx_bpf_task_cpu(p);
	if (cpu < 0)
		return;

	blk = inf_block(cpu);
	if (!blk)
		return;

	/* The task leaves the old parent. */
	if (tctx->state == INF_ENTITY_RUNNABLE) {
		inf_task_leave_tree(tctx);
	} else if (tctx->state == INF_ENTITY_SELECTED ||
		   tctx->state == INF_ENTITY_RUNNING) {
		/*
		 * The task holds a path. The path is released, and the
		 * task enters the tree of the destination cgroup.
		 */
		inf_task_leave(tctx);
	}

	/* The destination parent. */
	cgrp = to ? to : inf_task_cgroup(p);
	leaf_parent = inf_resolve_leaf(blk, cgrp, &cgrp_id);
	leaf	 = inf_entity(blk, leaf_parent);
	if (!leaf)
		return;

	tctx->parent_idx = leaf_parent;
	tctx->cgrp_id    = cgrp_id;

	/*
	 * The task starts at the frontier of the destination parent. The
	 * source value is not carried across the parent coordinate.
	 */
	tctx->v_q16 = leaf->frontier_q16;
	tctx->queued_cpu = cpu;
	tctx->path_cpu   = cpu;
	tctx->state = INF_ENTITY_INACTIVE;

	inf_admit_task(blk, tctx, leaf_parent, INF_INS_NORMAL);
	INF_STAT_INC(cgrp_cpu_moves);
}

/*
 * The cgroup control state. The scheduler reads the weight and the idle
 * flag of a cgroup from its own map, so a group entity can be refreshed
 * by the cgroup id alone.
 */
static __noinline int inf_cgroup_state_put(struct cgroup *cgrp, u32 weight,
					   bool idle)
{
	struct inf_cgrp_state st = {};
	u64			id;

	if (!cgrp)
		return -EINVAL;

	id = inf_cgroup_id(cgrp);
	if (!id)
		return 0;

	st.cgrp_id = id;
	st.weight  = weight;
	st.idle    = idle ? 1 : 0;
	st.present = 1;
	st.epoch   = scx_cgroup_ctl_epoch();

	if (bpf_map_update_elem(&cgrp_state_stor, &id, &st, BPF_ANY))
		INF_STAT_INC(ctl_map_overflow);
	return 0;
}

s32 BPF_STRUCT_OPS(infinity_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	int ret;

	TOUCH_ARENA();

	ret = scx_cgroup_ctl_cgroup_init(cgrp, args);
	if (ret)
		return ret;

	return inf_cgroup_state_put(cgrp, args ? args->weight : INF_WEIGHT_DEFAULT,
				    args ? args->sched_idle : false);
}

void BPF_STRUCT_OPS(infinity_cgroup_exit, struct cgroup *cgrp)
{
	u64 id;

	TOUCH_ARENA();

	scx_cgroup_ctl_cgroup_exit(cgrp);

	if (!cgrp)
		return;

	id = inf_cgroup_id(cgrp);
	if (id)
		bpf_map_delete_elem(&cgrp_state_stor, &id);
}

void BPF_STRUCT_OPS(infinity_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 id;

	TOUCH_ARENA();

	scx_cgroup_ctl_set_weight(cgrp, weight);

	if (!cgrp)
		return;

	id = inf_cgroup_id(cgrp);
	if (!id)
		return;

	{
		struct inf_cgrp_state *st = inf_cgrp_state(id);

		if (st) {
			__sync_fetch_and_add(&st->epoch, 1);
			WRITE_ONCE(st->weight, weight);
		}
	}
}

void BPF_STRUCT_OPS(infinity_cgroup_set_idle, struct cgroup *cgrp, bool idle)
{
	u64 id;

	TOUCH_ARENA();

	scx_cgroup_ctl_set_idle(cgrp, idle);

	if (!cgrp)
		return;

	id = inf_cgroup_id(cgrp);
	if (!id)
		return;

	{
		struct inf_cgrp_state *st = inf_cgrp_state(id);

		if (st) {
			__sync_fetch_and_add(&st->epoch, 1);
			WRITE_ONCE(st->idle, idle ? 1 : 0);
		}
	}
}

void BPF_STRUCT_OPS(infinity_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	int ret = scx_cgroup_ctl_set_bandwidth(cgrp, period_us, quota_us,
					       burst_us);

	if (ret)
		scx_bpf_error("Failed to set cgroup bandwidth: %d", ret);
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
	 * The entity store of every possible CPU: the group entities, the
	 * cgroup index and the occupancy bitmap. The block lives in the BPF
	 * arena and is never resized; a CPU index selects an entry.
	 */
	pages = (ncpu * (u32)sizeof(*inf_blocks) + PAGE_SIZE - 1) / PAGE_SIZE;
	inf_blocks = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!inf_blocks) {
		scx_bpf_error("infinity: failed to allocate %u entity pages",
			      pages);
		return -ENOMEM;
	}
	inf_nr_blocks = ncpu;

	/* The root entity of every CPU is slot 0 and always exists. */
	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		inf_cpu_block_t	  *blk;
		inf_group_entity_t *root;

		if ((u32)cpu >= ncpu)
			break;

		blk = inf_block(cpu);
		if (!blk)
			continue;

		root = inf_entity(blk, 0);
		__builtin_memset(root, 0, sizeof(*root));
		root->cgrp_id = 0;
		root->weight  = INF_WEIGHT_DEFAULT;
		root->parent_idx = 0;
		root->state	 = INF_ENTITY_RUNNABLE;
		inf_queue_init(&root->children);
		inf_queue_node_init(&root->qnode);
		/* The root entity occupies slot 0 for the whole run. */
		blk->bitmap[0] |= 1;
		blk->nr_used = 1;
	}

	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		if (cpu < 0)
			continue;
		key  = (u32)cpu;
		cctx = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cctx) {
			cctx->root_idx		= 0;
			cctx->depth		= 0;
			cctx->seq		= 0;
			cctx->steal_llc_cursor	= 0;
			cctx->steal_node_cursor = 0;
			cctx->resv.pid		= 0;
			cctx->resv.flags	= 0;
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
	 * Snapshot the trees while the arena still owns them, so the exit
	 * dump names the queue and task state of a stalled run.
	 */
	inf_dump_queues();
	inf_trace_seal();

	/*
	 * The arena owns the entity store. Drop the scheduler pointer before
	 * the map is destroyed; no callback runs after ops.exit().
	 */
	inf_blocks    = NULL;
	inf_nr_blocks = 0;
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(infinity_ops, .select_cpu = (void *)infinity_select_cpu,
	       .enqueue		     = (void *)infinity_enqueue,
	       .dispatch	     = (void *)infinity_dispatch,
	       .dequeue		     = (void *)infinity_dequeue,
	       .running		     = (void *)infinity_running,
	       .stopping	     = (void *)infinity_stopping,
	       .quiescent	     = (void *)infinity_quiescent,
	       .tick		     = (void *)infinity_tick,
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
