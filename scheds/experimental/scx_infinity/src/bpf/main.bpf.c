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

/*
 * Feature bisection switch of the stall diagnosis.
 *
 * The variant is a compile-time choice, not a rodata or map field: the
 * dispatch program sits close to the verifier instruction budget, and one
 * extra branch inside the selection costs more than the variant is worth.
 * Each variant is a build in which the named mechanism is absent from the
 * binary, which is also what makes the result interesting: the variant
 * that removes the stall names the mechanism that causes it.
 *
 *   0  every mechanism on, which is the shipped policy
 *   1  preemption off: no SCX_KICK_PREEMPT path
 *   2  steal off: the local tree only
 *   3  reservations off: charge at the stop, no epoch deferral
 *   4  flat hierarchy: every task is a direct child of the root entity
 *   5  fixed 5 ms slice: the core slice expires, the tick never ends a slot
 */
#define INF_BISECT_NONE 0
#define INF_BISECT_NO_PREEMPT 1
#define INF_BISECT_NO_STEAL 2
#define INF_BISECT_INLINE_CHARGE 3
#define INF_BISECT_FLAT_TREE 4
#define INF_BISECT_FIXED_SLICE 5

#ifndef INF_BISECT_VARIANT
#define INF_BISECT_VARIANT 0
#endif

#define INF_FIXED_SLICE_NS 5000000ULL

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
 * The persistent dispatch snapshot, one entry per possible CPU.
 *
 * It is written when a local selection returns no leaf, before the steal
 * overwrites the selection scratch of that CPU, and it is never cleared.
 * The map is pinned in bpffs, so the entry survives the scheduler process:
 * the exit dump of main.rs runs after the disable pass and cannot show a
 * state the disable pass has already rewritten. A stalled run reads the
 * entry through bpftool, and a clean run shows that the depth, retry,
 * zero-count and scan reasons of the selection never happened.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_MAX_CPUS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, u32);
	__type(value, struct inf_dispatch_snap);
} dsnap_stor SEC(".maps");

/*
 * The tick-side and dispatch-side core snapshot, one ring per CPU, pinned
 * like the dispatch snapshot.
 *
 * A stalled CPU is idle: the core's current task is the idle task, so
 * ops.tick() does not run there and the runnable tasks that the watchdog
 * names are not visible through any per-task callback. The record is taken
 * from the callbacks that do run on that CPU, which are the dispatch and
 * the tick, and it carries the core's own count of queued tasks. A CPU
 * whose record shows the core counting queued tasks while the tree counts
 * none is a CPU whose tasks are in core custody with no scheduler
 * reference; a CPU whose record shows the tree holding tasks while the
 * selection hands out none is a tree the selection cannot reach.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_MAX_CPUS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, u32);
	__type(value, struct inf_core_snap);
} csnap_stor SEC(".maps");

/*
 * The last enqueue and the last dispatch submission of one task, indexed
 * by the low bits of the pid and pinned like the core snapshot.
 *
 * A task that strands in the core's custody is in no queue of this
 * scheduler, and an idle CPU runs no per-task callback, so the policy
 * structures cannot name it. This record is written at the enqueue that
 * can strand it and the watchdog names the pid, so the two together
 * attribute the loss to the enqueue, to the dispatch submission, or to a
 * missing follow-up event.
 *
 * The key is the pid with the low bits of the map size, and the record
 * carries the full pid, so a reader can reject an entry that a colliding
 * task overwrote. The record is written for an SCX_ENQ_LAST enqueue and
 * for an enqueue or hand-back that failed. A pid with no record was
 * enqueued normally and lost its ownership some other way.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INF_ENQ_SNAP_MAX);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, u32);
	__type(value, struct inf_enq_rec);
} enq_stor SEC(".maps");

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
	struct scx_edq	    children;
	u64		    v_q16;
	u64		    rem;
	u64		    frontier_q16;
	u64		    cgrp_id;
	u64		    count;
	u64		    tie;
	u64		    tie_seq;
	u64		    epoch;
	u64		    generation;
	u32		    parent_idx;
	u32		    weight;
	u32		    gate_seq;
	u32		    class;
	u16		    nr_children;
	u16		    flags;
	u32		    refs;
	u32		    state;
	u32 idle; /* a cpu.idle flag is at or above this entity */
};

typedef struct inf_group_entity __arena inf_group_entity_t;

/*
 * The candidate of a band scan. The node is held while the scan runs and
 * the winner keeps its hold until the caller removes it.
 */
struct inf_cand {
	scx_edq_task_t *task;
	u64		v;
	u64		tie;
	u32		cls;
	bool		valid;
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
typedef u8 __arena		      inf_byte_t;

/*
 * The entity store of one CPU: the group entities, the cgroup index and
 * the occupancy bitmap of the entity slots. Slot 0 of the entity array is
 * the root entity and always exists.
 */
struct inf_cpu_block {
	struct inf_group_entity ents[INF_GROUPS_PER_CPU];
	struct inf_index_slot	index[INF_INDEX_SLOTS];
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
	 * The queues the last selection attempt inspected, and why it
	 * returned no leaf. The dispatch copies this into dsnap_stor before
	 * the steal reuses the scratch, so a stalled CPU keeps a record of
	 * the selection that handed out nothing.
	 */
	struct inf_sel_level sel[INF_SEL_DEPTH_MAX];
	u32		     sel_levels;
	u32		     sel_attempts;
	u32		     sel_reason;
	u32		     sel_cause;
	/*
	 * The band scans of this CPU that reached INF_BAND_SCAN_MAX, and
	 * whether the first uninspected child was a node or the end of the
	 * walk. The counter is copied into the persistent snapshot.
	 */
	u64 band_full;
	u64 band_tail_node;
	u64 band_tail_null;
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
 * The queue entry points.
 *
 * The verifier validates a subprogram once per distinct entry state, and
 * the queue calls of the tree differ at every call site: each one holds a
 * different arena pointer, because a group entity, a task and the child
 * queue of a parent are different objects. Taking the two pointers as
 * `void __arena *` keeps the entry state of the callee equal across the
 * call sites, so the EDQ insert and remove are validated once instead of
 * once per site. Without this the dispatch program exceeds the verifier
 * instruction limit.
 */
static __noinline int inf_q_insert(void __arena *queue, void __arena *node,
				   u64 v)
{
	return scx_edq_insert((scx_edq_t *)queue, (scx_edq_task_t *)node, v, 0,
			      0);
}

static __noinline int inf_q_remove(void __arena *queue, void __arena *node)
{
	int ret =
		scx_edq_try_remove((scx_edq_t *)queue, (scx_edq_task_t *)node);

	if (ret == -EBUSY)
		ret = scx_edq_remove((scx_edq_t *)queue,
				     (scx_edq_task_t *)node);
	return ret;
}

/*
 * Per-task context, allocated in the arena by scx_task_alloc(). The
 * bandwidth context must stay first: REGISTER_SCX_CGROUP_BW_ENQUEUE_CB()
 * and the scx_cgroup_bw_* API cast the context to scx_task_common at offset
 * 0. The queue node follows it and is embedded for the task's whole
 * lifetime.
 */
struct task_ctx {
	struct scx_task_cgroup_bw cg_bw; /* MUST be first */
	struct scx_edq_task	  qnode; /* link in the parent group queue */
	u64			  v_q16; /* service on the parent scale */
	u64			  rem; /* retained division remainder */
	u64			  tie; /* insertion counter in the parent */
	u64 latched_weight; /* weight of the next charge */
	u64 epoch; /* epoch of the latched weight */
	u64 parent_idx; /* the leaf parent entity */
	u64 cgrp_id; /* the cgroup of the leaf parent */
	u64 slice_ns; /* the last assigned slice */
	u64 last_running_ns; /* clock at the last ops.running() */
	u64 base_weight;
	u64 pending_weight; /* p->scx.weight at the last change */
	u32 path_ent[INF_MAX_LEVELS]; /* the held path, leaf parent first */
	s32 queued_cpu; /* the CPU whose tree holds the task */
	s32 path_cpu;
	s32 cgrp_cpu; /* the CPU whose tree holds the path */
	u32 path_depth; /* the number of group levels */
	u32 state; /* enum inf_entity_state */
	u32 class; /* the insertion class */
	u32 moving; /* one writer owns a queue move */
	u32 dequeue_pending; /* a dequeue arrived during a move */
	u32 exit_pending; /* an exit arrived during a move */
	u32 reweight_pending; /* apply the new weight at the next step */
	u32 joined; /* the cgroup counts this task */
	u32 yielded; /* the task asked to yield */
	u32 preempted; /* the task lost its slice to a preemption */
	u32 wake_fork; /* the wakeup carried SCX_WAKE_FORK */
	u32 idle; /* the task sits under an idle group */
	u32 pid;
	u32 pending_event; /* the event of the ending slot */
	u32 hist_idx;
	struct inf_hist hist[8];
	/*
	 * The enqueue and submission record. enq_gen counts every enqueue so
	 * a published inf_enq_rec can be told apart from a later one, and
	 * last_dsq_ret keeps the result of the last local DSQ submission for
	 * this task.
	 */
	u64 enq_gen;
	u64 last_enq_flags;
	s64 last_dsq_ret;
};

typedef struct task_ctx __arena task_ctx;

/* The entity store. One block per possible CPU, never resized. */
static inf_cpu_block_t *inf_blocks;
static u32		inf_nr_blocks;

/*
 * The scheduler-private cgroup generation. A cgroup id can be reused
 * after an exit, so a new control entry takes a new value and an entity
 * compares it before it trusts its history.
 */
static u64 inf_gen_counter;

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
	u64 end	 = base + (u64)sizeof(blk->ents);

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
static __always_inline task_ctx *inf_task_from_qnode(scx_edq_task_t *node)
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
						      u32	       idx)
{
	if (idx >= INF_GROUPS_PER_CPU)
		return NULL;
	return &blk->ents[idx];
}

/* The index of an entity inside its block. */
static __always_inline u32 inf_entity_index(inf_cpu_block_t    *blk,
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
 * The measured service slot of a CPU.
 *
 * The tick probe seeds the slot from the measured scx_bpf_now() delta of
 * a local reservation. Until the seed exists, and after any out-of-range
 * update, the nominal slot is used. A slot is never promised as a fixed
 * wall-clock interval.
 */
static __always_inline u64 inf_cpu_slot_ns(s32 cpu)
{
	struct inf_cpu_ctx *cctx = inf_cpu_ctx(cpu);
	u64		    slot;

#if INF_BISECT_VARIANT == 5
	/* Variant 5: one fixed 5 ms slice, ended by the core, not the tick. */
	return INF_FIXED_SLICE_NS;
#else
	if (!cctx)
		return INF_SLOT_NS;
	slot = READ_ONCE(cctx->slot_ns);
	if (slot < INF_SLOT_MIN_NS || slot > INF_SLOT_MAX_NS)
		return INF_SLOT_NS;
	return slot;
#endif
}

/*
 * Open the reservation of one running slot.
 *
 * It records the CPU, the ancestry from the leaf parent to the root, the
 * latched weight of every level, the reserved slot and the actual-runtime
 * cursor. The cursor stays zero until ops.running() sets it, which is the
 * same call that opens the reservation.
 */
static __noinline void inf_resv_open(struct inf_cpu_ctx *cctx, task_ctx *tctx,
				     s32 cpu)
{
	struct inf_reservation *r   = &cctx->resv;
	inf_cpu_block_t	       *blk = inf_block(tctx->path_cpu);
	u32			i;

	r->task_idx  = tctx->pid;
	r->start_now = 0;
	r->policy_ns = 0;
	r->slot_ns   = inf_cpu_slot_ns(cpu);
	r->cpu	     = (u32)cpu;
	r->depth     = 0;
	r->flags     = 0;

	if (!blk)
		goto done;

	r->depth = tctx->path_depth;
	if (r->depth > INF_MAX_LEVELS)
		r->depth = INF_MAX_LEVELS;

	for (i = 0; i < INF_MAX_LEVELS && can_loop; i++) {
		inf_group_entity_t *e;

		if (i >= r->depth)
			break;
		r->ancestry[i] = tctx->path_ent[i];
		e	       = inf_entity(blk, r->ancestry[i]);
		r->latched[i]  = e ? e->weight : INF_WEIGHT_DEFAULT;
	}
done:
	INF_STAT_INC(resv_open);
}

/*
 * The reservation that belongs to @tctx, or NULL.
 *
 * One CPU runs one task at a time and one slot is open per CPU. A task with
 * a held path keeps its slot on the CPU of that path. A task without one, a
 * restored current task or an exit hand-back, keeps its slot on the CPU it
 * runs on, so the callback that looks for the slot looks there too.
 *
 * The owner is always the task identity: a slot of another task is never
 * returned, so a settle can only ever close the slot of the task it charges.
 */
static __always_inline struct inf_cpu_ctx *inf_resv_ctx(task_ctx *tctx)
{
	struct inf_cpu_ctx *cctx;

	cctx = inf_cpu_ctx(tctx->path_cpu);
	if (cctx && cctx->resv.task_idx == tctx->pid)
		return cctx;

	cctx = inf_cpu_ctx(bpf_get_smp_processor_id());
	if (cctx && cctx->resv.task_idx == tctx->pid)
		return cctx;

	return NULL;
}

/*
 * Close a slot whose owner no longer runs on this CPU.
 *
 * A start on a CPU means the previous task of that CPU has already stopped:
 * ops.stopping() of the outgoing task runs before set_next_task() of the new
 * one. A slot that still names another task is therefore not live, and leaving
 * it open would stop the CPU from accounting for good. The start closes it
 * without charging it to anyone and counts it, so a run names every case.
 */
static __always_inline void inf_resv_reclaim(struct inf_cpu_ctx *cctx,
					     task_ctx		*tctx)
{
	if (!cctx->resv.task_idx || cctx->resv.task_idx == tctx->pid)
		return;

	INF_STAT_INC(resv_stale);
	cctx->resv.task_idx  = 0;
	cctx->resv.start_now = 0;
	cctx->resv.policy_ns = 0;
	cctx->resv.depth     = 0;
	cctx->resv.flags     = 0;
}

/* True when this callback runs on the CPU that owns the reservation. */
static __always_inline bool inf_resv_local(struct inf_cpu_ctx *cctx)
{
	return cctx && bpf_get_smp_processor_id() == (s32)cctx->resv.cpu;
}

/*
 * Attach a task to the group entity that holds it. The entity keeps one
 * reference for the task, so it cannot be reclaimed while the task is
 * queued, running or parked. A task that moves to another CPU or cgroup
 * drops the old reference first.
 */
static __noinline void inf_task_attach(task_ctx *tctx, inf_cpu_block_t *blk,
				       s32 cpu, u32 leaf);
static __noinline void inf_task_detach(task_ctx *tctx);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_task_pool);
} task_pool_stor SEC(".maps");

/*
 * The live task contexts of the arena pool. One lookup per init and per
 * exit, and one per stats interval from user space.
 */
static __always_inline struct inf_task_pool *inf_task_pool(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&task_pool_stor, &key);
}

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

/*
 * The diagnostic snapshot table. The map is an LRU hash of the last
 * INF_TASK_SNAP_MAX distinct tasks: a task that exits stays readable for
 * the exit dump while a newer task pushes it out, so the table is bounded
 * without a delete on the exit path. A plain hash was exhausted by the pid
 * churn of a fork workload, and every later snapshot update then failed:
 * the ring kept recording but the per-task history was frozen on the pids
 * of the first minute. The counter `task_overflow` is still kept, and a
 * nonzero value now means a real update error, not the steady state of a
 * full table.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inf_fault_ctl);
} fault_stor SEC(".maps");

/*
 * The controlled-refusal map of the steal and yield-to tests. A normal
 * run never arms it, so the lookup returns zeroed counters and every test
 * hook takes its unarmed branch.
 */
static __always_inline struct inf_fault_ctl *inf_fault(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&fault_stor, &key);
}

/*
 * Take one forced refusal from @counter. The decrement is atomic, so two
 * CPUs cannot both use one armed probe. Returns false when the counter is
 * zero.
 */
static __always_inline bool inf_fault_take(u64 *counter)
{
	if (!counter || !READ_ONCE(*counter))
		return false;
	__sync_fetch_and_add(counter, -1);
	return true;
}

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
 * traffic and `overwritten` stays zero, which is what the stall campaign
 * requires: a non-zero value means the anomalous-event record is
 * incomplete. `total` counts every transition; `next` counts ringed ones.
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
 * Record the tree position of a task in its snapshot. The selection reaches
 * a task only through the child queue of its leaf entity and, above it, the
 * child queue of every ancestor. A task whose node is in no queue, whose
 * node sits in another queue, or whose leaf or ancestor left its own parent
 * queue is unreachable, and the snapshot says which of the three it is.
 *
 * The fields are read without a lock: the snapshot is a diagnostic record of
 * the moment of the transition, and a concurrent change can only make it
 * stale, never wrong about the queue the node was in.
 */
static __noinline void inf_snap_path(task_ctx *tctx, struct inf_task_snap *snap)
{
	inf_cpu_block_t	   *blk;
	inf_group_entity_t *e;
	scx_edq_t	   *owner;
	u32		    idx, broken = 0, level;

	snap->node_owner   = 0;
	snap->leaf_state   = 0xff;
	snap->leaf_count   = 0;
	snap->chain_broken = 0;
	snap->path_depth   = tctx->path_depth;
	snap->leaf_idx	   = -1;
	snap->leaf_cpu	   = -1;

	owner		   = inf_queue_node_owner(&tctx->qnode);
	if (owner)
		snap->node_owner = 2;

	blk = inf_block(tctx->queued_cpu);
	if (!blk)
		return;

	e = inf_entity(blk, (u32)tctx->parent_idx);
	if (!e)
		return;

	snap->leaf_idx	 = (s32)inf_entity_index(blk, e);
	snap->leaf_cpu	 = tctx->queued_cpu;
	snap->leaf_state = e->state;
	snap->leaf_count = (s64)e->count;
	if (owner == &e->children)
		snap->node_owner = 1;

	for (level = 0; level < INF_MAX_LEVELS && can_loop; level++) {
		inf_group_entity_t *par;

		idx = e->parent_idx;
		if (!idx)
			break;
		par = inf_entity(blk, idx);
		if (!par)
			break;
		if (e->state != INF_ENTITY_RUNNABLE ||
		    inf_queue_node_owner(&e->qnode) != &par->children)
			broken++;
		e = par;
	}
	snap->chain_broken = broken;
}

/* True when a RUNNABLE task cannot be reached from the root of its tree. */
static __always_inline bool inf_path_lost(task_ctx	       *tctx,
					  struct inf_task_snap *snap)
{
	if (tctx->state != INF_ENTITY_RUNNABLE)
		return false;
	return snap->node_owner != 1 || snap->chain_broken != 0;
}

/*
 * Record a task that is RUNNABLE but whose node sits in no queue, or in a
 * queue other than the child queue of its own leaf entity. Such a task is in
 * the custody of the core and in no queue the selection can reach, so the
 * record carries the operation that left it there in its result field and the
 * ring holds every occurrence.
 */
static __noinline void inf_trace_path_lost(task_ctx *tctx, u32 op)
{
	struct inf_trace_ctl *ctl;
	struct inf_trace_rec *rec;
	u32		      key = 0;
	u64		      idx;
	u32		      slot;

	ctl = bpf_map_lookup_elem(&trace_ctl_stor, &key);
	if (ctl) {
		idx  = __sync_fetch_and_add(&ctl->next, 1);
		slot = (u32)idx & (INF_TRACE_CAP - 1);
		rec  = bpf_map_lookup_elem(&trace_stor, &slot);
		if (rec) {
			rec->ts	       = bpf_ktime_get_ns();
			rec->seq       = idx;
			rec->slice     = tctx->slice_ns;
			rec->result    = (s64)op;
			rec->pid       = (s32)tctx->pid;
			rec->src_cpu   = tctx->queued_cpu;
			rec->dst_cpu   = tctx->path_cpu;
			rec->op	       = INF_TR_PATH_LOST;
			rec->state     = tctx->state;
			rec->hold      = inf_queue_node_hold(&tctx->qnode);
			rec->group_cpu = tctx->parent_idx;
		}
		if (idx >= INF_TRACE_CAP)
			__sync_fetch_and_add(&ctl->overwritten, 1);
	}

	{
		u32 slot2		 = tctx->hist_idx & 7;

		tctx->hist[slot2].op	 = INF_TR_PATH_LOST;
		tctx->hist[slot2].src	 = tctx->queued_cpu;
		tctx->hist[slot2].dst	 = (s32)op;
		tctx->hist[slot2].result = (s32)tctx->parent_idx;
		tctx->hist[slot2].state	 = tctx->state;
		tctx->hist_idx++;
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
		u32 slot		= tctx->hist_idx & 7;

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

	inf_snap_path(tctx, snap);
	if (inf_path_lost(tctx, snap)) {
		INF_STAT_INC(runnable_unlinked);
		inf_trace_path_lost(tctx, op);
	}

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
		scx_edq_task_t	      *head;
		task_ctx	      *tctx;

		if (cpu >= ncpu)
			break;

		qs = bpf_map_lookup_elem(&qsnap_stor, &cpu);
		if (!qs)
			continue;

		blk  = inf_block((s32)cpu);
		cctx = inf_cpu_ctx((s32)cpu);
		if (!blk || !cctx)
			continue;

		__builtin_memset(qs, 0, sizeof(*qs));
		qs->cpu	     = (s32)cpu;
		qs->depth    = READ_ONCE(cctx->depth);
		qs->local_nr = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);

		root	     = inf_entity(blk, 0);
		if (!root)
			continue;

		head = (scx_edq_task_t *)root->children.first;
		if (!head)
			continue;

		if (inf_node_is_group(blk, (u64)head)) {
			inf_group_entity_t *e = (inf_group_entity_t *)head;

			qs->head_pid	      = 0;
			qs->head_weight	      = e->weight;
			qs->head_key	      = e->v_q16;
			qs->head_state	      = e->state;
			qs->head_hold	      = inf_queue_node_hold(head);
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
 * Arm the trace from ops.init(), before the first transition. The ring
 * control entry is a map value and starts zeroed, so a cap that is written
 * only by the exit path reads as zero for the whole run: the periodic stats
 * then report cap=0 and the exit dump cannot map a sequence number to a
 * slot. Writing cap, enabled and the counters here makes the entry
 * describe the live ring from the first dispatch on.
 */
static __noinline void inf_trace_arm(void)
{
	struct inf_trace_ctl *ctl;
	u32		      key = 0;

	ctl			  = bpf_map_lookup_elem(&trace_ctl_stor, &key);
	if (!ctl)
		return;
	WRITE_ONCE(ctl->next, 0);
	WRITE_ONCE(ctl->overwritten, 0);
	WRITE_ONCE(ctl->task_overflow, 0);
	WRITE_ONCE(ctl->total, 0);
	WRITE_ONCE(ctl->cap, INF_TRACE_CAP);
	WRITE_ONCE(ctl->enabled, enable_trace ? 1 : 0);
}

/*
 * Write the exit status of the trace into the control entry, so the
 * loader knows whether the ring ran over before it reads it. The cap and
 * enabled fields are written again here because an exit can follow a run
 * whose init never armed the trace.
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
 * Record the callback that is starting on this CPU. The history names the
 * last three callbacks of the CPU, so a record that shows an idle core can
 * still say whether that CPU dispatched, and a CPU that never asked for
 * work is told apart from a CPU that asked and received nothing.
 */
static __always_inline void inf_cb_note(u32 tag)
{
	s32		    cpu = bpf_get_smp_processor_id();
	struct inf_cpu_ctx *cctx;
	u32		    slot;

	if (cpu < 0 || (u32)cpu >= inf_nr_cpu_ids())
		return;

	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	slot	       = cctx->cb_next & (INF_CB_HISTORY - 1);
	cctx->cb[slot] = tag;
	cctx->cb_next++;
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
	struct inf_cgrp_state *st      = inf_cgrp_state(cgrp_id);
	u32		       w       = INF_WEIGHT_DEFAULT;
	bool		       is_idle = false;

	if (st) {
		w	= st->weight;
		is_idle = st->idle != 0;
		if (idle)
			*idle = is_idle;
	}
	if (w < INF_WEIGHT_MIN)
		w = INF_WEIGHT_MIN;
	if (w > INF_WEIGHT_MAX)
		w = INF_WEIGHT_MAX;
	/*
	 * A caller that does not ask for the flag still gets the idle
	 * weight: the entity is created once, and a wrong weight at creation
	 * would stand until the next epoch bump.
	 */
	if (is_idle)
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
							  int		 level)
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
	*v     = *v + delta;
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
	inf_index_slot_t *s    = &blk->index[inf_index_start(cgrp_id)];
	inf_index_slot_t *end  = &blk->index[INF_INDEX_SLOTS];
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
	inf_index_slot_t *s    = &blk->index[inf_index_start(cgrp_id)];
	inf_index_slot_t *end  = &blk->index[INF_INDEX_SLOTS];
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
			/*
			 * A stale entity of an exited cgroup still owns
			 * this slot. It is not overwritten: its tasks and
			 * children still reference it, so a second entity
			 * for the same id would split the history. The
			 * caller falls back to an ancestor until the
			 * stale entity is reclaimed.
			 */
			if (s->ent_idx != ent_idx)
				return -EEXIST;
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
	inf_index_slot_t *s    = &blk->index[inf_index_start(cgrp_id)];
	inf_index_slot_t *end  = &blk->index[INF_INDEX_SLOTS];
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
					u32 parent_idx, u32 weight, bool idle)
{
	inf_group_entity_t    *e;
	struct inf_cgrp_state *st;
	u32		       idx;

	if (inf_bitmap_alloc(blk, &idx)) {
		INF_STAT_INC(entity_alloc_fail);
		return INF_IDX_NONE;
	}

	e = inf_entity(blk, idx);
	if (!e) {
		inf_bitmap_free(blk, idx);
		return INF_IDX_NONE;
	}

	e->v_q16 = 0;
	e->rem	 = 0;
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
	e->refs		= 0;
	e->state	= INF_ENTITY_INACTIVE;
	e->idle		= idle ? 1 : 0;
	st		= inf_cgrp_state(cgrp_id);
	e->generation	= st ? st->gen : 0;

	inf_queue_init(&e->children);
	inf_queue_node_init(&e->qnode);

	if (inf_index_insert(blk, cgrp_id, idx)) {
		/*
		 * -EEXIST means a stale entity of an exited cgroup still
		 * owns the index and has references. The caller falls back
		 * to an ancestor; the stale slot is reclaimed when its last
		 * reference drops.
		 */
		inf_bitmap_free(blk, idx);
		INF_STAT_INC(entity_reuse_busy);
		return INF_IDX_NONE;
	}

	/* The new child keeps one reference on its parent. */
	{
		inf_group_entity_t *par = inf_entity(blk, parent_idx);

		if (par && parent_idx != idx)
			par->refs++;
	}

	return idx;
}

/*
 * Release one entity slot. The entity must have no live reference: no
 * attached task, no dispatchable descendant and no held path. A reclaim
 * that finds a reference marks the entity dead and keeps the slot until
 * the last reference drops.
 */
static __noinline void inf_entity_release(inf_cpu_block_t *blk, u32 idx)
{
	inf_group_entity_t *e = inf_entity(blk, idx);
	inf_group_entity_t *par;

	if (!e)
		return;

	if (e->refs || e->count || e->state == INF_ENTITY_SELECTED ||
	    e->state == INF_ENTITY_RUNNING || e->state == INF_ENTITY_HANDOFF) {
		/*
		 * A task, a child entity or a running path still holds the
		 * entity. The cgroup is gone, so the entity stays dead and
		 * is released when the last reference drops.
		 */
		e->state = INF_ENTITY_EXITING;
		INF_STAT_INC(entity_ref_busy);
		INF_STAT_INC(reclaims_deferred);
		return;
	}

	if (e->state == INF_ENTITY_RUNNABLE) {
		par = inf_entity(blk, e->parent_idx);
		if (par)
			inf_q_remove(&par->children, &e->qnode);
	}

	/* Only the index entry that still points at this slot is removed. */
	if (inf_index_find(blk, e->cgrp_id) == idx)
		inf_index_remove(blk, e->cgrp_id);

	par = inf_entity(blk, e->parent_idx);
	if (par && e->parent_idx != idx && par->refs)
		par->refs--;

	inf_bitmap_free(blk, idx);
	e->state   = INF_ENTITY_EXITING;
	e->count   = 0;
	e->cgrp_id = 0;
	INF_STAT_INC(entity_reclaims);
}

/* Add one reference to the entity at @idx. */
static __always_inline void inf_ref_inc(inf_cpu_block_t *blk, u32 idx)
{
	inf_group_entity_t *e = inf_entity(blk, idx);

	if (e)
		e->refs++;
}

/*
 * Drop one reference. A dead entity that loses its last reference is
 * reclaimed here. The release never drops another reference itself, so
 * this is a single call chain and not recursion.
 */
static __noinline void inf_ref_dec(inf_cpu_block_t *blk, u32 idx)
{
	inf_group_entity_t *e = inf_entity(blk, idx);

	if (!e)
		return;
	if (e->refs)
		e->refs--;
	if (!e->refs && e->state == INF_ENTITY_EXITING)
		inf_entity_release(blk, idx);
}

/*
 * Attach a task to the group entity that holds it. The entity keeps one
 * reference for the task, so it cannot be reclaimed while the task is
 * queued, running or parked. A task that moves to another CPU or cgroup
 * drops the old reference first.
 */
static __noinline void inf_task_attach(task_ctx *tctx, inf_cpu_block_t *blk,
				       s32 cpu, u32 leaf)
{
	if (tctx->joined && tctx->parent_idx == leaf && tctx->cgrp_cpu == cpu)
		return;

	inf_task_detach(tctx);

	tctx->parent_idx = leaf;
	tctx->cgrp_cpu	 = cpu;
	tctx->joined	 = 1;
	inf_ref_inc(blk, leaf);
}

/* Drop the reference that a task keeps on its cgroup entity. */
static __noinline void inf_task_detach(task_ctx *tctx)
{
	inf_cpu_block_t *blk;
	u32		 idx;

	if (!tctx->joined)
		return;

	blk = inf_block(tctx->cgrp_cpu);
	idx = (u32)tctx->parent_idx;
	if (blk)
		inf_ref_dec(blk, idx);

	tctx->joined   = 0;
	tctx->cgrp_cpu = -1;
}

/*
 * The entity of one cgroup on this CPU, or INF_IDX_NONE. A cgroup that
 * has exited has no live entry, so its entity is stale and the slot is
 * reclaimed here. A reused cgroup id takes a new generation, so an entity
 * of the old cgroup never charges the new one.
 */
static __noinline u32 inf_lookup_entity(inf_cpu_block_t *blk, u64 cgrp_id)
{
	struct inf_cgrp_state *st;
	inf_group_entity_t    *e;
	u32		       idx = inf_index_find(blk, cgrp_id);

	if (idx == INF_IDX_NONE)
		return INF_IDX_NONE;

	st = inf_cgrp_state(cgrp_id);
	if (!st) {
		inf_entity_release(blk, idx);
		return INF_IDX_NONE;
	}

	e = inf_entity(blk, idx);
	if (!e)
		return INF_IDX_NONE;

	if (e->generation != st->gen) {
		INF_STAT_INC(entity_stale_gen);
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
static __noinline u32 inf_resolve_leaf(inf_cpu_block_t *blk,
				       struct cgroup *cgrp, u64 *cgrp_id_out)
{
	u32 parent = 0;
	int level;
	int i;

	*cgrp_id_out = 0;
	if (!cgrp)
		return 0;

	level = BPF_CORE_READ(cgrp, level);
	if (level > INF_MAX_LEVELS)
		level = INF_MAX_LEVELS;

	for (i = 1; i <= INF_CHAIN_MAX && can_loop; i++) {
		struct cgroup *anc;
		u64	       id;
		u32	       idx;

		if (i > level)
			break;
		anc = inf_cgroup_ancestor(cgrp, i);
		if (!anc)
			break;

		id  = inf_cgroup_id(anc);
		idx = inf_lookup_entity(blk, id);
		if (idx == INF_IDX_NONE) {
			bool idle   = false;
			u32  weight = inf_cgroup_weight(id, &idle);

			idx = inf_entity_create(blk, id, parent, weight, idle);
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

/*
 * The verdict of one admission without a state change, and the commit of
 * that admission. A transactional insert reads the verdict, attempts the
 * insert, and commits the gate and the tie only when the insert succeeded,
 * so a refused insert leaves the destination gate where it was.
 */
static __always_inline u32 inf_gate_peek(inf_group_entity_t *parent, u32 mode,
					 u64 *tie)
{
	u64 seq;

	seq  = READ_ONCE(parent->gate_seq);
	*tie = READ_ONCE(parent->tie_seq);

	if (mode == INF_INS_TAIL)
		return INF_CLASS_TAIL;
	if (mode == INF_INS_HEAD)
		return INF_CLASS_HEAD;
	if ((seq & INF_GATE_MASK) == INF_GATE_MASK)
		return INF_CLASS_TAIL;
	return INF_CLASS_HEAD;
}

static __always_inline void inf_gate_commit(inf_group_entity_t *parent,
					    u32			mode)
{
	if (mode == INF_INS_NORMAL)
		__sync_fetch_and_add(&parent->gate_seq, 1);
	__sync_fetch_and_add(&parent->tie_seq, 1);
}

/* Insert a group entity into the queue of its parent. */
static __always_inline int inf_link_entity(inf_cpu_block_t    *blk,
					   inf_group_entity_t *e, u32 mode)
{
	inf_group_entity_t *par = inf_entity(blk, e->parent_idx);
	int		    ret;

	if (!par)
		return -ENOENT;

	e->v_q16 = inf_service_max(e->v_q16, par->frontier_q16);
	e->class = inf_gate_class(par, mode);
	e->tie	 = par->tie_seq++;
	ret	 = inf_q_insert(&par->children, &e->qnode, e->v_q16);
	if (ret) {
		/*
		 * The entity is not in its parent queue, so nothing below
		 * it is reachable from the root. Marking it RUNNABLE here
		 * would hide every descendant from the selection and move
		 * no counter, so the failure is recorded and the entity
		 * stays INACTIVE. Its children are still in its own child
		 * queue; the caller repairs the path.
		 */
		INF_STAT_INC(link_lost);
		return ret;
	}
	e->state = INF_ENTITY_RUNNABLE;
	return 0;
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
		bool		    dormant;

		if (!e)
			return;
		dormant = e->count == 0;
		e->count++;
		if (!dormant) {
			/*
			 * A counted entity must sit in its parent queue. A
			 * counted entity that is not linked cannot be reached
			 * by the selection, so the tasks below it stall.
			 */
			if (e->state != INF_ENTITY_RUNNABLE)
				INF_STAT_INC(link_lost);
			return;
		}
		if (inf_link_entity(blk, e, mode))
			return;
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
			inf_group_entity_t *par =
				inf_entity(blk, e->parent_idx);

			/*
			 * The entity leaves its parent queue because its
			 * last counted child left. A child that is still
			 * queued here is not counted, so the entity is about
			 * to unlink a non-empty queue: the child is stranded
			 * and the selection can never reach it.
			 */
			if (inf_queue_nr(&e->children))
				INF_STAT_INC(count_lost);
			if (par)
				inf_q_remove(&par->children, &e->qnode);
			e->state = INF_ENTITY_INACTIVE;
		}
		idx = e->parent_idx;
	}
}

/*
 * Put the ancestors of a task back after a refused steal. The removal
 * took them out of their parent queues but kept their service value and
 * their insertion record, so the restore re-links them with that record
 * and advances no gate.
 */
static __noinline void inf_restore_up(inf_cpu_block_t *blk, u32 idx)
{
	u32 i;

	for (i = 0; i < INF_MAX_LEVELS && idx != 0 && can_loop; i++) {
		inf_group_entity_t *e = inf_entity(blk, idx);
		inf_group_entity_t *par;
		bool		    dormant;

		if (!e)
			return;
		dormant = e->count == 0;
		e->count++;
		if (!dormant)
			return;
		par = inf_entity(blk, e->parent_idx);
		if (!par)
			return;
		e->v_q16 = inf_service_max(e->v_q16, par->frontier_q16);
		if (inf_q_insert(&par->children, &e->qnode, e->v_q16))
			INF_STAT_INC(state_repairs);
		e->state = INF_ENTITY_RUNNABLE;
		idx	 = e->parent_idx;
	}
}

/*
 * The service value of the head of a queue. The head carries the minimum
 * service of the queue, so it is the band minimum. The read takes no lock
 * and changes no state: a queue that changes under the read can only make
 * a band check refuse, which is the safe direction.
 */
static __always_inline void inf_node_info(inf_cpu_block_t *blk, u64 node,
					  u64 *v, u32 *cls, u64 *tie);

static __always_inline bool
inf_queue_head_v(inf_cpu_block_t *blk, inf_group_entity_t *parent, u64 *vmin)
{
	scx_edq_node_t *hn = parent->children.first;
	u64		v, tie;
	u32		cls;

	if (!hn)
		return false;
	inf_node_info(blk, (u64)inf_queue_node_task(hn), &v, &cls, &tie);
	*vmin = v;
	return true;
}

/*
 * The service value, the insertion class and the tie of a queued child.
 */
static __always_inline void inf_node_info(inf_cpu_block_t *blk, u64 node,
					  u64 *v, u32 *cls, u64 *tie)
{
	if (inf_node_is_group(blk, node)) {
		inf_group_entity_t *e = (inf_group_entity_t *)node;

		*v		      = e->v_q16;
		*cls		      = e->class;
		*tie		      = e->tie;
	} else {
		task_ctx *t = inf_task_from_qnode((scx_edq_task_t *)node);

		*v	    = t->v_q16;
		*cls	    = t->class;
		*tie	    = t->tie;
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
static __always_inline u64 inf_band_better(u64 v, u32 cls, u64 tie, u64 best_v,
					   u32 best_cls, u64 best_tie)
{
	u64 c	       = cls;
	u64 b	       = best_cls;
	u64 diff       = v - best_v;
	u64 lt	       = (diff >> 63) & 1;
	u64 gt	       = ((best_v - v) >> 63) & 1;
	u64 eq	       = 1 - lt - gt;
	u64 n_head     = 1 - ((c | (0 - c)) >> 63);
	u64 b_head     = 1 - ((b | (0 - b)) >> 63);
	u64 head_wins  = n_head & (1 - b_head);
	u64 same       = 1 - (n_head ^ b_head);
	u64 tie_newer  = ((best_tie - tie) >> 63) & 1;
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
	scx_edq_node_t		*n;
	scx_edq_task_t		*best	  = NULL;
	u64			 best_v	  = 0;
	u64			 best_tie = 0;
	u32			 best_cls = 0;
	u64			 vmin	  = 0;
	u32			 scanned  = 0;
	bool			 have	  = false;
	int			 ret	  = 0;

	*truncated			  = false;
	win->valid			  = false;

	if (inf_queue_lock(queue))
		return -EBUSY;

	n				   = queue->first;
	scratch->counter[INF_COUNTER_BAND] = 0;
	while (n && can_loop) {
		scx_edq_task_t *task = inf_queue_node_task(n);
		u64		v, tie, inb, take, mask, first;
		u32		cls;

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
			vmin = v;
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

		inb	 = inf_in_band_mask(v, vmin);
		take	 = (inf_band_better(v, cls, tie, best_v, best_cls,
					    best_tie) |
			    first) &
			   inb;
		mask	 = 0 - take;

		best_v	 = (best_v & ~mask) | (v & mask);
		best_tie = (best_tie & ~mask) | (tie & mask);
		best_cls = (best_cls & ~mask) | (cls & mask);
		best	 = (scx_edq_task_t *)(((u64)best & ~mask) |
					      ((u64)task & mask));

		n	 = inf_queue_next(n);
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

	/*
	 * The loop stops on the bound before it inspects the next child, so
	 * n is the first child the scan did not visit. It is NULL when the
	 * queue ran out exactly at the bound: inf_queue_next() dereferences
	 * node->right (queue.h), so the walk must not advance it again. The
	 * old code did, and an arena READ fault at offset 0x10 of a NULL node
	 * was that read, not a corrupt tree link.
	 */
	if (scanned >= INF_BAND_SCAN_MAX) {
		/*
		 * The three counters live in the block, so the scan takes no
		 * map pointer and keeps no state across the queue lock. A
		 * later selection failure copies them into the persistent
		 * snapshot, and they are cumulative, so a copy taken after a
		 * full scan still reports that scan.
		 */
		__sync_fetch_and_add(&scratch->band_full, 1);

		if (n) {
			scx_edq_task_t *nt = inf_queue_node_task(n);
			u64		nv, ntie;
			u32		ncls;

			__sync_fetch_and_add(&scratch->band_tail_node, 1);
			inf_node_info(blk, (u64)nt, &nv, &ncls, &ntie);
			if (inf_in_band_mask(nv, vmin)) {
				*truncated = true;
				INF_STAT_INC(band_scan_truncated);
			}
		} else {
			__sync_fetch_and_add(&scratch->band_tail_null, 1);
		}
	}

	inf_queue_unlock(queue);

	if (best) {
		win->valid = true;
		win->task  = best;
		win->v	   = best_v;
		win->tie   = best_tie;
		win->cls   = best_cls;
	}

	*vmin_out = vmin;
	return ret;
}

/*
 * The identity of one child of a parent queue.
 *
 * A raw arena address cannot be stored in a map value, so a group entity is
 * named by its entity index and a task by its pid. Both name the child
 * across a dump, and the index is also what a later lookup takes.
 */
static __always_inline void inf_child_identity(inf_cpu_block_t *blk,
					       scx_edq_node_t *node, s32 *id,
					       u32 *is_group)
{
	scx_edq_task_t *t;

	*id	  = -1;
	*is_group = 0;
	if (!node)
		return;

	t = inf_queue_node_task(node);
	if (inf_node_is_group(blk, (u64)t)) {
		*id	  = (s32)inf_entity_index(blk, (inf_group_entity_t *)t);
		*is_group = 1;
		return;
	}
	*id = (s32)inf_task_from_qnode(t)->pid;
}

/*
 * Record one parent queue that the current selection attempt inspected.
 *
 * Only the fields that the failure path cannot rebuild are stored here: the
 * owner, the depth, the queue minimum, the scan return and the identity of
 * the winner. Everything else is read back from the entities when the
 * persistent snapshot is taken. The function is inlined, and the split is
 * not cosmetic: every field written here costs verifier states in the
 * dispatch program, which is at the instruction limit, while the failure
 * path runs once per failed selection.
 */
static __always_inline void inf_sel_note(inf_cpu_block_t *blk,
					 inf_cpu_block_t *scratch, u32 depth,
					 u32 parent, u64 vmin, int scan)
{
	struct inf_sel_level __arena *lvl;
	u32			      is_group;
	s32			      id;

	if (depth >= INF_SEL_DEPTH_MAX)
		return;

	lvl	    = &scratch->sel[depth];
	lvl->depth  = depth;
	lvl->parent = parent;
	lvl->vmin   = vmin;
	lvl->scan   = (u32)scan;
	lvl->child  = INF_IDX_NONE;
	lvl->pid    = -1;
	lvl->flags  = 0;

	if (scratch->win.valid) {
		inf_child_identity(blk, &scratch->win.task->node, &id,
				   &is_group);
		if (is_group) {
			lvl->child = (u32)id;
			lvl->flags |= INF_SEL_F_WIN_GROUP;
		} else {
			lvl->pid = id;
		}
	}

	if (scratch->sel_levels <= depth)
		scratch->sel_levels = depth + 1;
}

/*
 * Descend from the root of the tree and return the leaf task and the path
 * that holds it. The scan changes no key, no gate, no service and no
 * frontier. The caller applies the frontier when it commits the
 * selection.
 *
 * The descent inspects INF_SEL_DEPTH_MAX queues: the root queue, one queue
 * per group descent, and the terminal queue that holds the task. A chain of
 * INF_MAX_LEVELS group levels therefore ends at depth INF_MAX_LEVELS, which
 * is the terminal inspection. A group entity found at that depth is deeper
 * than the chain builder can produce, so the selection refuses it and names
 * the level instead of writing past path->ent[].
 */
static __noinline bool
inf_select_leaf(inf_cpu_block_t *blk, inf_cpu_block_t *scratch, task_ctx **leaf)
{
	struct inf_path __arena *path = &scratch->path;
	u32			 attempt;
	u32			 parent	 = 0;
	u32			 cause	 = 0;
	bool			 restart = false;
	int			 ret;

	scratch->sel_levels   = 0;
	scratch->sel_attempts = 0;
	scratch->sel_reason   = INF_SEL_EMPTY;
	scratch->sel_cause    = 0;

	/*
	 * Both counters live in the arena, so the verifier sees imprecise
	 * values and analyses one descent in one converging state instead of
	 * once per attempt and level. The dispatch program is at the
	 * verifier instruction limit and an unrolled terminal level does not
	 * fit. The bounds are the same.
	 */
	scratch->counter[INF_COUNTER_RETRY] = 0;
	while (can_loop) {
		attempt = scratch->counter[INF_COUNTER_RETRY];
		if (attempt >= INF_SELECT_RETRY_MAX)
			break;
		scratch->counter[INF_COUNTER_RETRY] = attempt + 1;

		restart				    = false;
		parent				    = 0;
		scratch->sel_levels		    = 0;
		scratch->sel_attempts		    = attempt + 1;
		scratch->counter[INF_COUNTER_DEPTH] = 0;

		/*
		 * INF_SEL_DEPTH_MAX inspections: the root queue, one queue
		 * per group descent, and the terminal queue that holds the
		 * task. A four-level chain ends at the terminal queue, which
		 * the selection used to leave uninspected.
		 */
		while (can_loop) {
			inf_group_entity_t *pe;
			u32		    depth;
			u64		    vmin  = 0;
			bool		    trunc = false;

			/*
			 * One load, so the verifier can bound the value it
			 * indexed: after the check the index is inside
			 * path->vmin[].
			 */
			depth = scratch->counter[INF_COUNTER_DEPTH];
			if (depth >= INF_SEL_DEPTH_MAX)
				break;
			scratch->counter[INF_COUNTER_DEPTH] = depth + 1;

			pe = inf_entity(blk, parent);
			if (!pe) {
				scratch->sel_reason = INF_SEL_NO_ENTITY;
				return false;
			}

			ret = inf_band_scan(blk, &pe->children, scratch,
					    pe->frontier_q16, &vmin, &trunc);
			/*
			 * Record the queue before the branch, so a refused
			 * scan and a stale winner leave the same record as a
			 * good one.
			 */
			inf_sel_note(blk, scratch, depth, parent, vmin, ret);
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
						inf_q_remove(&par->children,
							     &pe->qnode);
					pe->state = INF_ENTITY_INACTIVE;
					pe->count = 0;
					INF_STAT_INC(state_repairs);
					cause	= INF_SEL_EMPTY;
					restart = true;
					break;
				}
				scratch->sel_reason = ret == -ENOENT ?
							      INF_SEL_EMPTY :
							      INF_SEL_SCAN;
				return false;
			}

			path->vmin[depth] = vmin;

			if (inf_node_is_group(blk, (u64)scratch->win.task)) {
				inf_group_entity_t *e =
					(inf_group_entity_t *)scratch->win.task;

				if (e->count == 0) {
					/*
					 * A group without a dispatchable
					 * descendant is stale. Remove it and
					 * start the selection again.
					 */
					inf_group_entity_t *par =
						inf_entity(blk, e->parent_idx);

					if (par)
						inf_q_remove(&par->children,
							     &e->qnode);
					e->state = INF_ENTITY_INACTIVE;
					INF_STAT_INC(state_repairs);
					inf_queue_drop(scratch->win.task);
					cause	= INF_SEL_ZERO_COUNT;
					restart = true;
					break;
				}

				/*
				 * A group at the terminal depth has no queue
				 * left to inspect. The chain builder caps the
				 * entity chain at INF_MAX_LEVELS group levels,
				 * so this is a tree defect. Refuse it here
				 * instead of writing path->ent[] one past its
				 * last element.
				 */
				if (depth >= INF_MAX_LEVELS) {
					scratch->sel_reason = INF_SEL_DEPTH;
					inf_queue_drop(scratch->win.task);
					return false;
				}

				path->ent[depth] = inf_entity_index(blk, e);
				parent		 = path->ent[depth];
				inf_queue_drop(scratch->win.task);
				continue;
			}

			/* The winner is a task: the leaf of the path. */
			path->depth = depth;
			*leaf	    = inf_task_from_qnode(scratch->win.task);
			inf_queue_drop(scratch->win.task);
			return true;
		}

		if (restart)
			continue;

		/*
		 * The bound was reached with a group still on the path: the
		 * same defect as a group found at the terminal depth.
		 */
		scratch->sel_reason = INF_SEL_DEPTH;
		return false;
	}

	scratch->sel_reason = INF_SEL_RETRY;
	scratch->sel_cause  = cause;
	return false;
}

/*
 * The service minimum of every queue the selection inspected becomes the
 * frontier of that queue. The frontier never decreases.
 *
 * The terminal queue counts too. The selected task is the band minimum of
 * the queue that held it, and that queue advances to the same frontier as
 * every queue above it: a task that re-enters later must not be able to
 * pass the task that was just selected. The terminal queue is at depth
 * path->depth and its owner is path->ent[path->depth - 1], or the root
 * entity for a task of the root cgroup.
 */
static __always_inline void inf_apply_frontier(inf_cpu_block_t	       *blk,
					       struct inf_path __arena *path)
{
	u32 i, depth = path->depth;

	if (depth >= INF_SEL_DEPTH_MAX)
		depth = INF_SEL_DEPTH_MAX - 1;

	for (i = 0; i <= depth && can_loop; i++) {
		inf_group_entity_t *par;
		u32 vi = i < INF_SEL_DEPTH_MAX ? i : INF_SEL_DEPTH_MAX - 1;

		if (i == 0) {
			par = inf_entity(blk, 0);
		} else {
			u32 pi = i - 1;

			if (pi >= INF_MAX_LEVELS)
				pi = INF_MAX_LEVELS - 1;
			par = inf_entity(blk, path->ent[pi]);
		}

		if (!par)
			continue;
		par->frontier_q16 =
			inf_service_max(par->frontier_q16, path->vmin[vi]);
	}
}

/*
 * The advisory depth of a tree. It counts the runnable tasks of the tree
 * and steers the placement scan only.
 *
 * It is a counter of the tasks this scheduler has admitted to that tree, so
 * it can never be negative: a decrement that finds nothing counted is a
 * bookkeeping defect, and the counter is clamped and named instead of going
 * below zero. A negative depth used to make inf_local_work() and the empty
 * selection record read as an empty tree, which hid the tasks the tree still
 * held.
 */
static __always_inline void inf_depth_add(s32 cpu, s64 delta)
{
	struct inf_cpu_ctx *cctx = inf_cpu_ctx(cpu);
	s64		    now;

	if (!cctx)
		return;

	now = __sync_fetch_and_add(&cctx->depth, delta) + delta;
	if (now < 0) {
		INF_STAT_INC(depth_under);
		WRITE_ONCE(cctx->depth, 0);
	}
}

/*
 * Check the advisory depth of @cpu against the count of the root entity.
 *
 * The root entity counts every runnable task below it, because inf_count_up()
 * advances each ancestor of an admission and inf_count_down() takes it back on
 * a removal. The number of tasks in the tree is therefore the root count, and
 * a depth that disagrees with it is a leak or a lost link. The check runs on
 * the cold path only, and the depth is repaired from the authoritative count
 * so the placement scan and the selection record see the tree that exists.
 */
static __noinline void inf_depth_sync(s32 cpu)
{
	struct inf_cpu_ctx	*cctx = inf_cpu_ctx(cpu);
	inf_cpu_block_t		*blk  = inf_block(cpu);
	inf_group_entity_t	*root;
	u64			 count;
	s64			 depth;

	if (!cctx || !blk)
		return;

	root = inf_entity(blk, 0);
	if (!root)
		return;

	count = READ_ONCE(root->count);
	depth = READ_ONCE(cctx->depth);
	if ((u64)(depth < 0 ? 0 : depth) == count)
		return;

	INF_STAT_INC(depth_mismatch);
	WRITE_ONCE(cctx->depth, (s64)count);
}

/*
 * Put a task into the tree. The leaf parent is the entity of the task's
 * cgroup on this CPU.
 */
static __always_inline void inf_refresh_weight(inf_group_entity_t *e);

static __noinline int	    inf_admit_task(inf_cpu_block_t *blk, task_ctx *tctx,
					   u32 leaf_parent, u32 mode)
{
	inf_group_entity_t *parent = inf_entity(blk, leaf_parent);

	if (!parent) {
		INF_STAT_INC(admit_no_parent);
		INF_STAT_INC(lost_state_errors);
		return -EINVAL;
	}

	/* A dormant or queued group refreshes before the next charge. */
	inf_refresh_weight(parent);

	tctx->v_q16 = inf_service_max(tctx->v_q16, parent->frontier_q16);
	tctx->class = inf_gate_class(parent, mode);
	tctx->tie   = parent->tie_seq++;
	if (inf_q_insert(&parent->children, &tctx->qnode, tctx->v_q16)) {
		/*
		 * The node is still linked in another queue. A stale
		 * membership would leave the task invisible to the tree,
		 * so the node is unlinked and the insert is retried.
		 */
		if (inf_queue_unlink(&tctx->qnode)) {
			INF_STAT_INC(lost_state_errors);
			return -EINVAL;
		}
		if (inf_q_insert(&parent->children, &tctx->qnode,
				 tctx->v_q16)) {
			INF_STAT_INC(lost_state_errors);
			return -EINVAL;
		}
		INF_STAT_INC(state_repairs);
	}
	/*
	 * The task sits in the child queue of @parent. A leaf that is not
	 * linked in its own parent queue cannot be reached by the selection,
	 * so the record names the broken link instead of hiding it. The count
	 * and the link are checked after the count-up, because a first task in
	 * a dormant leaf links it as part of that step.
	 */
	tctx->state = INF_ENTITY_RUNNABLE;
	inf_count_up(blk, leaf_parent, mode);
	inf_depth_add(tctx->queued_cpu, 1);

	if (leaf_parent != 0) {
		inf_group_entity_t *par = inf_entity(blk, parent->parent_idx);

		if (parent->state != INF_ENTITY_RUNNABLE ||
		    (par &&
		     inf_queue_node_owner(&parent->qnode) != &par->children))
			INF_STAT_INC(admit_unlinked);
	}
	return 0;
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
	inf_cpu_block_t	   *blk = inf_block(tctx->path_cpu);
	inf_group_entity_t *e;
	u32		    i;

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

		inf_refresh_weight(e);
		inf_q_remove(&par->children, &e->qnode);
		if (new_record) {
			e->class = inf_gate_class(par, mode);
			e->tie	 = par->tie_seq++;
		}
		if (inf_q_insert(&par->children, &e->qnode, e->v_q16))
			INF_STAT_INC(rekey_fail);
	}
}

/*
 * The path of a task re-enters the tree. The leaf task and every ancestor
 * on the path take their own insertion class in their own parent queue.
 */
static __noinline int inf_requeue_path(task_ctx *tctx, u32 mode)
{
	inf_cpu_block_t	   *blk = inf_block(tctx->path_cpu);
	inf_group_entity_t *leaf;

	if (!blk) {
		INF_STAT_INC(requeue_no_block);
		INF_STAT_INC(lost_state_errors);
		return -EINVAL;
	}

	leaf = inf_entity(blk, (u32)tctx->parent_idx);
	if (!leaf) {
		INF_STAT_INC(requeue_no_leaf);
		INF_STAT_INC(lost_state_errors);
		return -EINVAL;
	}

	inf_rekey_ancestors(tctx, true, mode);

	tctx->v_q16 = inf_service_max(tctx->v_q16, leaf->frontier_q16);
	tctx->class = inf_gate_class(leaf, mode);
	tctx->tie   = leaf->tie_seq++;
	if (inf_q_insert(&leaf->children, &tctx->qnode, tctx->v_q16)) {
		if (inf_queue_unlink(&tctx->qnode)) {
			INF_STAT_INC(lost_state_errors);
			return -EINVAL;
		}
		if (inf_q_insert(&leaf->children, &tctx->qnode, tctx->v_q16)) {
			INF_STAT_INC(lost_state_errors);
			return -EINVAL;
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
	return 0;
}

/* Remove a task from the tree and release the counts below it. */
static __noinline void inf_task_leave_tree(task_ctx *tctx)
{
	inf_cpu_block_t	   *blk = inf_block(tctx->queued_cpu);
	inf_group_entity_t *leaf;

	if (!blk)
		return;

	leaf = inf_entity(blk, (u32)tctx->parent_idx);
	if (!leaf)
		return;

	if (inf_q_remove(&leaf->children, &tctx->qnode)) {
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
	tctx->state	    = INF_ENTITY_INACTIVE;
	tctx->queued_cpu    = -1;
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
		tctx->state	    = INF_ENTITY_INACTIVE;
		tctx->path_depth    = 0;
		tctx->path_cpu	    = -1;
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
	u64		       epoch = scx_cgroup_ctl_epoch();
	u32		       w;

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
	e->rem	  = 0;
	e->epoch  = epoch;
	e->idle	  = st->idle ? 1 : 0;
}

/*
 * Charge the service of a slot to the task and to every ancestor of its
 * path. The leaf uses its latched weight. A group level uses the weight
 * the reservation latched at the dispatch when the reservation covers the
 * path, and the live weight otherwise. The entity refreshes its weight
 * only after the charge, so a running entity settles with the old weight
 * and observes a change at its next slot.
 */
static __noinline void inf_charge_path(task_ctx		      *tctx,
				       struct inf_reservation *r, u64 policy_ns)
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
		u32		    weight;

		if (i >= tctx->path_depth)
			break;
		e = inf_entity(blk, tctx->path_ent[i]);
		if (!e)
			continue;
		weight = e->weight;
		if (r && i < r->depth && r->ancestry[i] == tctx->path_ent[i])
			weight = (u32)r->latched[i];
		inf_charge_service(&e->v_q16, &e->rem, policy_ns, weight);
		inf_refresh_weight(e);
	}
}

/*
 * Apply a task weight that arrived while the task held a slot. The old
 * weight settled the slot; the new weight takes effect here and the
 * residue is flushed.
 */
static __always_inline void inf_apply_epoch(task_ctx *tctx)
{
	if (!tctx->reweight_pending)
		return;

	tctx->rem = 0;
	if (tctx->pending_weight)
		tctx->latched_weight = tctx->pending_weight;
	tctx->pending_weight   = 0;
	tctx->reweight_pending = 0;
	INF_STAT_INC(epoch_applied);
}

/*
 * Settle the open reservation of @tctx exactly once.
 *
 * The actual runtime is measured from the cursor that ops.running() set,
 * and only that value reaches cpu.max. The policy ledger receives the
 * actual runtime, except that an explicit yield raises the total to
 * max(actual, slot_ns) and debits only the difference.
 *
 * The settle closes the reservation, so a later callback charges nothing.
 */
static __noinline void inf_settle_slot(struct task_struct *p, task_ctx *tctx,
				       u32 event, bool local)
{
	struct inf_stats       *stats;
	struct inf_cpu_ctx     *cctx;
	struct inf_reservation *r;
	u64			actual = 0;
	u64			policy;
	u64			extra = 0;
	bool			yield;

	if (!tctx)
		return;

	cctx = inf_resv_ctx(tctx);
	if (!cctx) {
		/*
		 * No slot of this task is open. The slot of this CPU belongs
		 * to another task, so this settle must not touch it: a stop
		 * closes only the slot of the task it charges.
		 */
		INF_STAT_INC(resv_none);
		return;
	}

	/*
	 * The locality test is taken from the slot and not from the callback:
	 * a slot that a task opened on the CPU it ran on is settled with the
	 * actual runtime even when the callback runs elsewhere.
	 */
	local = inf_resv_local(cctx);

#if INF_BISECT_VARIANT == 3
	/*
	 * Variant 3: no reservation. The runtime is read from the cursor of
	 * the last ops.running() and charged here, so the slot is settled
	 * where the task stops and there is no deferred settlement.
	 */
	{
		u64 actual = 0;

		if (local && tctx->last_running_ns) {
			u64 now = scx_bpf_now();

			if (now > tctx->last_running_ns)
				actual = now - tctx->last_running_ns;
		}
		if (actual > INF_SETTLE_MAX_NS) {
			actual = INF_SETTLE_MAX_NS;
			INF_STAT_INC(settle_clamps);
		}
		inf_charge_path(tctx, NULL, actual);
		inf_apply_epoch(tctx);
		if (actual && p && inf_cpu_bw_enabled())
			scx_cgroup_ctl_consume(p, (u64)tctx, actual);
		return;
	}
#endif

	r = &cctx->resv;
	if (!r->task_idx) {
		/* The slot was already settled. */
		INF_STAT_INC(resv_closed);
		return;
	}
	if (r->task_idx != tctx->pid) {
		INF_STAT_INC(resv_mismatch);
		return;
	}

	if (local) {
		if ((r->flags & INF_RESV_RUNNING) && r->start_now) {
			u64 now = scx_bpf_now();

			if (now > r->start_now)
				actual = now - r->start_now;
		}
	} else {
		/*
		 * A remote callback cannot read the clock of the CPU that
		 * runs the task. It counts the reserved slot instead.
		 */
		actual = r->slot_ns;
		INF_STAT_INC(remote_slots);
		INF_STAT_INC(resv_remote);
	}

	if (actual > INF_SETTLE_MAX_NS) {
		actual = INF_SETTLE_MAX_NS;
		INF_STAT_INC(settle_clamps);
	}

	yield  = (event == INF_EV_YIELD) || (r->flags & INF_RESV_YIELD);
	policy = actual;
	if (yield && policy < r->slot_ns) {
		extra  = r->slot_ns - policy;
		policy = r->slot_ns;
		INF_STAT_INC(resv_yield);
	}

	/*
	 * The policy ledger. The actual runtime is charged first, then the
	 * yield difference. cpu.max sees only the actual runtime.
	 */
	inf_charge_path(tctx, r, actual);
	if (extra)
		inf_charge_path(tctx, r, extra);
	inf_apply_epoch(tctx);

	r->policy_ns = policy;
	r->task_idx  = 0;
	r->start_now = 0;
	r->depth     = 0;
	r->flags     = 0;

	stats	     = inf_stats();
	if (stats) {
		__sync_fetch_and_add(&stats->resv_settled, 1);
		__sync_fetch_and_add(&stats->resv_actual_ns, actual);
		__sync_fetch_and_add(&stats->resv_policy_ns, policy);
		if (extra)
			__sync_fetch_and_add(&stats->resv_yield_extra_ns,
					     extra);
	}

	/* The actual runtime is the only input to cpu.max. */
	if (actual && p && inf_cpu_bw_enabled())
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
 * Measure one local kernel tick.
 *
 * One ops.tick() call is one service slot, so the slot of a CPU is the
 * interval between two of its own ticks. The interval is the
 * scx_bpf_now() delta from the previous local tick of this CPU, and the
 * clock is only read on the CPU that owns it: a remote tick under
 * NOHZ_FULL carries no comparable clock and counts a slot instead.
 *
 * The first local tick of a CPU has no previous tick and only seeds the
 * clock. A zero or reversed delta means the tick cannot be measured on
 * this CPU; the count rises and a sustained failure blocks the run
 * instead of charging a fabricated slot. A gap longer than one settlement
 * is a CPU that did not tick for a while, so it is counted but kept out
 * of the slot average.
 */
static __noinline u64 inf_tick_measure(struct inf_cpu_ctx *cctx, u64 now,
				       bool local)
{
	struct inf_stats *stats;
	u64		  delta, slot;
	u32		  probe;

	if (!local)
		return 0;

	if (!cctx->tick_last) {
		cctx->tick_last = now;
		return 0;
	}

	if (now <= cctx->tick_last) {
		INF_STAT_INC(tick_unmeasurable);
		cctx->tick_bad++;
		if (cctx->tick_bad >= INF_TICK_UNMEASURABLE_MAX)
			scx_bpf_error(
				"infinity: the kernel tick cannot be measured on CPU %u",
				cctx->resv.cpu);
		return 0;
	}

	cctx->tick_bad	= 0;
	delta		= now - cctx->tick_last;
	cctx->tick_last = now;
	cctx->tick_deltas++;
	cctx->tick_sum_ns += delta;
	if (!cctx->tick_min_ns || delta < cctx->tick_min_ns)
		cctx->tick_min_ns = delta;
	if (delta > cctx->tick_max_ns)
		cctx->tick_max_ns = delta;

	/*
	 * A CPU that ran no task of this class for a while delivers its
	 * next tick late. The gap is a real interval, so it is counted, but
	 * folding it into the slot would widen the band and the slice for
	 * the following slots.
	 */
	if (delta > INF_SETTLE_MAX_NS) {
		INF_STAT_INC(tick_measured);
		return delta;
	}

	/* The measured slot is a decaying average of the real tick. */
	slot = cctx->slot_ns ? cctx->slot_ns : INF_SLOT_NS;
	slot = (slot * 7 + delta) / 8;
	if (slot < INF_SLOT_MIN_NS)
		slot = INF_SLOT_MIN_NS;
	if (slot > INF_SLOT_MAX_NS)
		slot = INF_SLOT_MAX_NS;
	cctx->slot_ns = slot;

	probe	      = cctx->tick_probe;
	if (probe < INF_TICK_PROBE_SLOTS) {
		cctx->tick_probe = probe + 1;
		if (cctx->tick_probe >= INF_TICK_PROBE_SLOTS) {
			stats = inf_stats();
			if (stats) {
				__sync_fetch_and_add(&stats->tick_probe_done,
						     1);
				WRITE_ONCE(stats->slot_ns_measured, slot);
				WRITE_ONCE(stats->slot_ns_min,
					   cctx->tick_min_ns);
				WRITE_ONCE(stats->slot_ns_max,
					   cctx->tick_max_ns);
			}
		}
	}

	INF_STAT_INC(tick_measured);
	return delta;
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
	u32		idx  = (u32)tctx->parent_idx;
	u32		level;

	/*
	 * The walk checks the queue of the leaf parent and the queue of every
	 * ancestor, the root queue included. A four-level chain has five
	 * queues on its path, so the bound is INF_MAX_LEVELS levels plus the
	 * root.
	 */
	for (level = 0; level <= INF_MAX_LEVELS && can_loop; level++) {
		inf_group_entity_t *pe = inf_entity(blk, idx);
		scx_edq_node_t	   *hn;
		scx_edq_task_t	   *head;
		u64		    head_v, cand_v;
		u32		    head_cls, cand_cls;
		u64		    tie;

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
		idx  = pe->parent_idx;
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
	inf_cpu_block_t	   *blk;
	struct task_struct *victim;
	struct inf_stats   *stats;
	u64		    reserve;
	task_ctx	   *tctx;
	bool		    fork;

	if (!(enq_flags & SCX_ENQ_WAKEUP)) {
		INF_STAT_INC(preempt_refuse_flags);
		return;
	}

#if INF_BISECT_VARIANT == 1
	/* Variant 1: no preemption kick at all. */
	return;
#endif

	INF_STAT_INC(preempt_checks);

	if (p->policy != INF_SCHED_NORMAL && p->policy != INF_SCHED_EXT) {
		INF_STAT_INC(preempt_refuse_policy);
		return;
	}

	tctx = inf_task_ctx(p);
	if (!tctx) {
		INF_STAT_INC(preempt_refuse_no_victim);
		return;
	}

	/*
	 * The fork marker belongs to one wakeup. Consume it here, whatever
	 * the decision is, so a marker cannot leak into the next wakeup.
	 */
	fork		= !!tctx->wake_fork;
	tctx->wake_fork = 0;
	if (fork) {
		INF_STAT_INC(preempt_refuse_fork);
		return;
	}
	if (tctx->idle) {
		INF_STAT_INC(preempt_refuse_idle);
		return;
	}

	/*
	 * The wakee must win its own queue and the queue of every
	 * ancestor under the band. The peek is read-only.
	 */
	blk = inf_block(tctx->queued_cpu);
	if (!blk) {
		INF_STAT_INC(preempt_refuse_no_victim);
		return;
	}
	if (!inf_wakee_wins(blk, tctx)) {
		INF_STAT_INC(preempt_refuse_not_winner);
		return;
	}

	victim = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!victim || victim == p) {
		INF_STAT_INC(preempt_refuse_no_victim);
		return;
	}
	if (!(victim->scx.flags & SCX_TASK_QUEUED)) {
		INF_STAT_INC(preempt_refuse_no_victim);
		return;
	}

	{
		struct inf_cfg *cfg = inf_cfg();

		reserve = cfg ? READ_ONCE(cfg->preempt_margin_ns) : 0;
	}
	/* The victim must retain strictly more than the margin. */
	if (READ_ONCE(victim->scx.slice) <= reserve) {
		INF_STAT_INC(preempt_refuse_slice);
		return;
	}

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
	inf_cb_note(INF_CB_SELECT_CPU);
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
				       s32 cpu, u32 mode, bool fresh_coord)
{
	inf_cpu_block_t	   *blk = inf_block(cpu);
	inf_group_entity_t *leaf;
	struct cgroup	   *cgrp;
	u64		    cgrp_id;
	u32		    leaf_parent;

	if (!blk)
		return -EINVAL;

	cgrp = inf_task_cgroup(p);
#if INF_BISECT_VARIANT == 4
	/*
	 * Variant 4: every task is a direct child of the root entity, so the
	 * tree has one queue and no group level.
	 */
	cgrp_id	    = inf_cgroup_id(cgrp);
	leaf_parent = 0;
#else
	leaf_parent = inf_resolve_leaf(blk, cgrp, &cgrp_id);
#endif

	leaf = inf_entity(blk, leaf_parent);
	if (!leaf)
		return -EINVAL;

	/*
	 * The preemption rule of the policy: a task under a cpu.idle group
	 * never preempts. The flag is read from the resolved path, so it
	 * covers every ancestor without a second cgroup walk.
	 */
	{
		u32  idx = leaf_parent;
		u32  i;
		bool idle = false;

		for (i = 0; i < INF_MAX_LEVELS && idx != 0 && can_loop; i++) {
			inf_group_entity_t *e = inf_entity(blk, idx);

			if (!e)
				break;
			if (e->idle) {
				idle = true;
				break;
			}
			idx = e->parent_idx;
		}
		tctx->idle = idle ? 1 : 0;
	}

	/* The task references the entity that holds it. */
	inf_task_attach(tctx, blk, cpu, leaf_parent);

	tctx->parent_idx = leaf_parent;
	tctx->cgrp_id	 = cgrp_id;
	tctx->queued_cpu = cpu;
	tctx->path_cpu	 = cpu;

	/*
	 * A new CPU or cgroup coordinate starts at the destination
	 * frontier. No source virtual time crosses the boundary.
	 */
	if (fresh_coord) {
		tctx->v_q16 = leaf->frontier_q16;
		tctx->rem   = 0;
	}

	/*
	 * A non-running entity refreshes its weight before the next
	 * charge. A deferred reweight keeps the value the settle will
	 * apply.
	 */
	if (!tctx->reweight_pending) {
		tctx->latched_weight = inf_task_weight(p);
		tctx->epoch	     = scx_cgroup_ctl_epoch();
	}

	return inf_admit_task(blk, tctx, leaf_parent, mode);
}

/*
 * The last-resort admission: the task re-enters the root entity of @cpu.
 *
 * A leaf admission is refused when the entity of the task's cgroup cannot be
 * resolved, when the task is not allowed to reference it, or when the insert
 * into the leaf queue fails twice. The task must not leave the tree
 * advertising an entity it does not hold, so the path is rolled back to the
 * root and the task is admitted there. Every tree has a root, the root has no
 * parent and no group level, and the selection reaches a task of the root
 * queue at depth zero, so a task that re-enters here is dispatchable again.
 *
 * Returns 0 when the task is in the root queue. A nonzero return means the
 * root queue itself refused the node, and the caller must hand the task to
 * the local DSQ instead of dropping it.
 */
static __noinline int inf_admit_root(struct task_struct *p, task_ctx *tctx,
				     s32 cpu, u32 mode, bool fresh_coord)
{
	inf_cpu_block_t	   *blk = inf_block(cpu);
	inf_group_entity_t *root;

	if (!blk)
		return -EINVAL;

	root = inf_entity(blk, 0);
	if (!root)
		return -EINVAL;

	/*
	 * The rollback: the reference of the refused leaf is dropped, the held
	 * path is cleared, and the task references the root before the insert.
	 * The node is unlinked from any queue it still claims, so the insert
	 * cannot fail with a stale membership.
	 */
	inf_queue_unlink(&tctx->qnode);
	inf_task_attach(tctx, blk, cpu, 0);

	tctx->parent_idx = 0;
	tctx->cgrp_id	 = 0;
	tctx->queued_cpu = cpu;
	tctx->path_cpu	 = cpu;
	tctx->path_depth = 0;

	if (fresh_coord) {
		tctx->v_q16 = root->frontier_q16;
		tctx->rem   = 0;
	}
	if (!tctx->reweight_pending) {
		tctx->latched_weight = inf_task_weight(p);
		tctx->epoch	     = scx_cgroup_ctl_epoch();
	}

	return inf_admit_task(blk, tctx, 0, mode);
}

/*
 * Publish the enqueue record of @tctx.
 *
 * The record is keyed by the low bits of the pid because the watchdog
 * names a stranded task by pid and an idle CPU holds no pointer to it; the
 * record carries the whole pid, so an entry that a colliding task
 * overwrote is recognisable. It is written for the enqueues that can
 * strand a task: one that carries SCX_ENQ_LAST, one whose tree admission
 * failed, and a refused hand-back. A task enqueued normally and lost some
 * other way keeps no record here, which is itself the attribution.
 *
 * The fields are stored through the map value pointer, not through an
 * update of a stack buffer: the enqueue and the dispatch programs sit
 * close to the verifier instruction budget, and a stack buffer with an
 * update call costs far more than the field stores.
 */
static __noinline void inf_enq_note(task_ctx *tctx, u64 enq_flags,
				    s64 admit_ret, u32 kick)
{
	struct inf_enq_rec *r;
	u32		    key = tctx->pid & (INF_ENQ_SNAP_MAX - 1);

	r			= bpf_map_lookup_elem(&enq_stor, &key);
	if (!r)
		return;

	r->ts	      = scx_bpf_now();
	r->enq_flags  = enq_flags;
	r->enq_gen    = tctx->enq_gen;
	r->admit_ret  = admit_ret;
	r->dsq_ret    = tctx->last_dsq_ret;
	r->pid	      = (s32)tctx->pid;
	r->state      = tctx->state;
	r->queued_cpu = tctx->queued_cpu;
	r->path_cpu   = tctx->path_cpu;
	r->kick	      = kick;
	r->path_depth = tctx->path_depth;

	INF_STAT_INC(enq_records);
}

/*
 * Shared enqueue path. @reenq marks a call from the bandwidth callback: the
 * cgroup has just become unthrottled, so the throttle check is skipped.
 */
static __noinline int inf_enqueue_common(struct task_struct *p, u64 enq_flags,
					 bool reenq)
{
	inf_cpu_block_t *blk;
	task_ctx	*tctx;
	u32		 mode;
	s32		 cpu;
	u32		 this_cpu;
	int		 ret;
	bool		 was_parked = false;
	bool		 fresh	    = false;

	if (!p)
		return -EINVAL;

	TOUCH_ARENA();

	this_cpu = bpf_get_smp_processor_id();
	cpu	 = scx_bpf_task_cpu(p);
	if (cpu < 0 || (u32)cpu >= inf_nr_cpu_ids())
		cpu = this_cpu;
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

	{
		struct inf_cpu_ctx *cc = inf_cpu_ctx(cpu);

		if (cc)
			cc->enq_calls++;
	}

	/*
	 * The enqueue generation. Every enqueue advances it, so a published
	 * record of inf_enq_rec can be told apart from a later enqueue of
	 * the same task, and the enqueue that stranded it stays named.
	 */
	tctx->enq_gen++;
	tctx->last_enq_flags = enq_flags;
	if (enq_flags & SCX_ENQ_LAST)
		INF_STAT_INC(enq_last);

	inf_trace(INF_TR_ENQ_ENTER, tctx,
		  INF_TR_WHERE(cpu, bpf_get_smp_processor_id()), enq_flags);

	/*
	 * An exiting task must not wait in the scheduler queue for a later
	 * dispatch: by then its pid can be gone, bpf_task_from_pid() fails,
	 * and the core keeps the task in custody until the watchdog. Hand it
	 * to the local DSQ now, while the task pointer is valid.
	 */
	if ((p->flags & PF_EXITING) || tctx->state == INF_ENTITY_EXITING) {
		if (enq_flags & SCX_ENQ_LAST)
			INF_STAT_INC(enq_last_exit);
		/*
		 * The slot is settled and the queue membership is dropped
		 * before the task is handed to the local DSQ, so a dead
		 * task never waits in the tree for a dispatch.
		 */
		inf_settle_slot(p, tctx, inf_slot_event(tctx),
				inf_resv_local(inf_cpu_ctx(tctx->path_cpu)));
		inf_task_leave(tctx);
		tctx->queued_cpu = -1;
		tctx->state	 = INF_ENTITY_EXITING;
		inf_trace(INF_TR_EXIT_PASS, tctx, INF_TR_WHERE(cpu, cpu), 3);
		if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0)) {
			INF_STAT_INC(exit_passes);
		} else {
			/*
			 * The core refused the hand-back. The task stays in
			 * this scheduler's hand, so the submission is the
			 * recorded cause and not a lost task.
			 */
			INF_STAT_INC(lost_state_errors);
			tctx->last_dsq_ret = -EAGAIN;
			inf_enq_note(tctx, enq_flags, 0, 0);
		}
		return 0;
	}

	/*
	 * A task in a throttled cgroup is parked in the bandwidth backlog and
	 * is not on any of our trees. The reservation is settled before the
	 * task leaves, so a parked task keeps its state and history but no
	 * open slot.
	 */
	if (inf_cpu_bw_enabled() && !reenq) {
		ret = scx_cgroup_ctl_throttled(p, (u64)tctx);
		if (ret == -EAGAIN) {
			if (!scx_cgroup_ctl_put_aside(p, (u64)tctx, 0)) {
				if (enq_flags & SCX_ENQ_LAST)
					INF_STAT_INC(enq_last_park);
				inf_settle_slot(p, tctx, inf_slot_event(tctx),
						bpf_get_smp_processor_id() ==
							tctx->path_cpu);
				inf_task_leave(tctx);
				tctx->state = INF_ENTITY_PARKED;
				INF_STAT_INC(cgrp_throttled);
				INF_STAT_INC(park_settled);
				inf_trace(INF_TR_ENQ_PARK, tctx,
					  INF_TR_WHERE(cpu, -1), ret);
				return 0;
			}
			/*
			 * A failed put-aside must not lose the task: fall
			 * through and enqueue it normally.
			 */
			INF_STAT_INC(park_failed);
		}
	}

	was_parked = tctx->state == INF_ENTITY_PARKED;

	/*
	 * The task holds a path: the slot ended and the path re-enters the
	 * tree. The event was recorded by the tick, or by the yield and the
	 * preemption.
	 */
	if ((tctx->state == INF_ENTITY_SELECTED ||
	     tctx->state == INF_ENTITY_RUNNING) &&
	    tctx->path_cpu == cpu) {
		u32  event = inf_slot_event(tctx);
		u32  mode  = inf_event_mode(event);
		bool local = this_cpu == cpu;
		s64  admit;
		u32  kick = 0;

		/*
		 * The settle closes the reservation. The tick already
		 * settled the slot, so a second settle charges nothing.
		 */
		inf_settle_slot(p, tctx, event, local);

		admit		    = inf_requeue_path(tctx, mode);
		tctx->pending_event = INF_EV_NONE;
		tctx->yielded	    = 0;
		tctx->preempted	    = 0;
		if (mode == INF_INS_TAIL)
			INF_STAT_INC(requeue_tail);
		else
			INF_STAT_INC(requeue_normal);
		inf_trace(INF_TR_REQUEUE, tctx,
			  INF_TR_WHERE(tctx->path_cpu, cpu), (s64)event);
		inf_resolve_pending(tctx);
		/*
		 * The path re-entered the tree of @cpu, and nothing of the
		 * core asks that CPU for another dispatch. Two cases need a
		 * deferred kick of that CPU:
		 *
		 * - The callback ran on another CPU. The owner of the tree
		 *   can be idle, and an idle CPU has nothing to wake it.
		 * - The enqueue carries SCX_ENQ_LAST. The core re-enqueues
		 *   the outgoing runnable task that way after a dispatch
		 *   that handed out nothing, and it keeps the CPU only if
		 *   the scheduler triggers another scheduling event. The
		 *   path here sits in the tree, not on a local DSQ, so
		 *   without the kick the CPU goes idle with the task
		 *   queued and the task waits for the watchdog.
		 */
		if ((enq_flags & SCX_ENQ_LAST) || !local) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			kick = 1;
			if (enq_flags & SCX_ENQ_LAST)
				INF_STAT_INC(enq_last_kicks);
		}
		if ((enq_flags & SCX_ENQ_LAST) || admit)
			inf_enq_note(tctx, enq_flags, admit, kick);
		return 0;
	}

	/*
	 * The task holds a path on another CPU. The old path is settled
	 * against the old CPU and released, and the task enters the tree of
	 * this CPU at the destination frontier. No source virtual time
	 * crosses the CPU boundary.
	 */
	if (tctx->state == INF_ENTITY_SELECTED ||
	    tctx->state == INF_ENTITY_RUNNING) {
		inf_settle_slot(p, tctx, inf_slot_event(tctx),
				inf_resv_local(inf_cpu_ctx(tctx->path_cpu)));
		inf_task_leave(tctx);
		fresh = true;
		INF_STAT_INC(resv_migrate);
	}

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
		if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0)) {
			tctx->last_dsq_ret = -EAGAIN;
			inf_enq_note(tctx, enq_flags, -EINVAL, 0);
		}
		return 0;
	}

	mode = (enq_flags & SCX_ENQ_HEAD) ? INF_INS_HEAD : INF_INS_NORMAL;

	if (inf_admit_on_cpu(p, tctx, cpu, mode, fresh)) {
		INF_STAT_INC(enq_admit_fail);

		/*
		 * The leaf refused the task. The refused admission rolled the
		 * leaf link back, so the task holds no entity and no path. It
		 * re-enters at the root, which is the one entity that every
		 * tree keeps, instead of leaving the tree for a local DSQ: a
		 * task the tree does not hold is a task no selection of this
		 * scheduler can reach, and that is the shape of the stall.
		 */
		if (!inf_admit_root(p, tctx, cpu, mode, fresh)) {
			INF_STAT_INC(admit_fallbacks);
			inf_trace(INF_TR_INSERT, tctx, INF_TR_WHERE(-1, cpu), 2);
			if (enq_flags & SCX_ENQ_LAST)
				inf_enq_note(tctx, enq_flags, 0, 1);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			inf_maybe_preempt(p, cpu, enq_flags);
			return 0;
		}

		/*
		 * Even the root refused the node. The core still counts the
		 * task as queued, so the local DSQ is the only hand-back left:
		 * the task runs, and the record names the refused admission.
		 */
		INF_STAT_INC(lost_state_errors);
		if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0))
			tctx->last_dsq_ret = -EAGAIN;
		inf_enq_note(tctx, enq_flags, -EINVAL, 0);
		return 0;
	}

	if (was_parked)
		INF_STAT_INC(unpark_admits);

	if (mode == INF_INS_HEAD)
		INF_STAT_INC(exempt_inserts);
	else if (tctx->class == INF_CLASS_TAIL)
		INF_STAT_INC(tail_inserts);
	else
		INF_STAT_INC(head_inserts);

	inf_trace(INF_TR_INSERT, tctx, INF_TR_WHERE(-1, cpu),
		  tctx->class == INF_CLASS_TAIL ? 1 : 0);

	/*
	 * The tree of @cpu now holds the task. A wakeup and a remote
	 * callback both need the owner of that tree to dispatch again, and
	 * so does an SCX_ENQ_LAST enqueue: the core hands the outgoing task
	 * back that way after a dispatch that handed out nothing, and it
	 * returns the CPU to idle unless the scheduler asks for another
	 * scheduling event. This task sits in the tree, not on a local DSQ,
	 * so the kick is the only thing that brings it back.
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) || (enq_flags & SCX_ENQ_LAST) ||
	    cpu != this_cpu) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		if (enq_flags & SCX_ENQ_LAST)
			INF_STAT_INC(enq_last_kicks);
	}

	if (enq_flags & SCX_ENQ_LAST)
		inf_enq_note(tctx, enq_flags, 0, 1);

	inf_maybe_preempt(p, cpu, enq_flags);
	return 0;
}

void BPF_STRUCT_OPS(infinity_enqueue, struct task_struct *p, u64 enq_flags)
{
	inf_cb_note(INF_CB_ENQUEUE);
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

/* One steal attempt, defined with the steal tiers below. */
static __noinline bool inf_steal_one(s32 cpu, struct inf_cpu_ctx *cctx,
				     task_ctx **out, u32 *leaf_out);

/*
 * Copy the selection scratch of @cpu into the persistent dispatch snapshot.
 *
 * This runs when the local selection found no leaf, before the steal reuses
 * the path and the counters of the block. The entry is written once per
 * failed selection and is never cleared, so the state of the last failure
 * outlives the scheduler: the exit dump of main.rs runs after the disable
 * pass and cannot show a tree that the disable pass has already emptied.
 *
 * The per-reason counters are the other half of the record. A stall that
 * aborts the scheduler leaves the reason of its last selection here, and a
 * clean run shows that the depth, retry, zero-count and scan reasons never
 * happened at all.
 */
/*
 * Write one core record of @cpu into the per-CPU ring.
 *
 * The record carries what the core holds for the CPU, so a stall is named
 * as one of two states. A tree that counts tasks while the selection hands
 * out none is a tree the selection cannot reach. An empty tree while the
 * core counts queued tasks is a task in core custody with no scheduler
 * reference: nothing in this scheduler can select it, and no per-task
 * callback will run for it again.
 *
 * `stranded` is that second state. A record with `stranded` set is the
 * proof that the task the watchdog names is in neither the tree nor a
 * dispatch queue, so the record is worth keeping from the callbacks that
 * still run on an otherwise idle CPU.
 */
static __noinline void inf_snap_core(s32 cpu, u32 tag, bool running_self)
{
	struct inf_core_snap  *snap;
	struct inf_core_entry *e;
	struct inf_cpu_ctx    *cctx;
	struct rq	      *rq;
	u32		       key = (u32)cpu;
	u64		       idx, nr_running = 0, local_nr = 0;
	u32		       i;

	snap = bpf_map_lookup_elem(&csnap_stor, &key);
	if (!snap)
		return;

	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	rq = scx_bpf_locked_rq();
	if (rq) {
		nr_running = rq->scx.nr_running;
		local_nr   = rq->scx.local_dsq.nr;
	}

	idx		= snap->next;
	snap->next	= idx + 1;
	e		= &snap->slot[idx & (INF_CORE_SNAP_SLOTS - 1)];

	e->ts		= scx_bpf_now();
	e->depth	= (u64)(cctx->depth > 0 ? cctx->depth : 0);
	e->nr_running	= nr_running;
	e->local_nr	= local_nr;
	e->last_disp_ns = cctx->last_disp_ns;
	e->resv_pid	= cctx->resv.task_idx;
	e->tag		= tag;
	/*
	 * The tasks the core counts on this runqueue that neither the tree
	 * nor the local DSQ holds, less the task that is running here. A
	 * nonzero value is a task in core custody with no scheduler
	 * reference: nothing in this scheduler can select it again.
	 */
	{
		s64 missing = (s64)nr_running - (s64)e->depth - (s64)local_nr -
			      (running_self ? 1 : 0);

		e->stranded = missing > 0 ? (u32)missing : 0;
	}
	e->curr_idle  = 0;
	e->curr_pid   = -1;
	e->curr_slice = 0;
	if (rq && rq->curr) {
		e->curr_pid   = rq->curr->pid;
		e->curr_slice = READ_ONCE(rq->curr->scx.slice);
		if (rq->curr == rq->idle)
			e->curr_idle = 1;
	}

	for (i = 0; i < INF_CB_HISTORY && can_loop; i++)
		e->cb[i] = cctx->cb[i];
	e->pad = cctx->cb_next;
}

/*
 * The core record of a CPU whose tick is worth keeping: the tree holds
 * tasks while the last dispatch handed out nothing for a while, or the
 * core counts queued tasks that the tree does not hold. A clean CPU writes
 * nothing, so an empty ring is a result and not a missing instrument.
 */
static __noinline void inf_snap_core_tick(s32 cpu, struct inf_cpu_ctx *cctx)
{
	struct rq *rq;
	u64	   nr_running = 0, local_nr = 0, depth, now;
	s64	   missing;

	if (!cctx)
		return;

	rq = scx_bpf_locked_rq();
	if (rq) {
		nr_running = rq->scx.nr_running;
		local_nr   = rq->scx.local_dsq.nr;
	}

	depth = cctx->depth > 0 ? (u64)cctx->depth : 0;
	/* This tick runs for the task the core is running here. */
	missing = (s64)nr_running - (s64)depth - (s64)local_nr - 1;

	/*
	 * The anomalous state only. A task the core counts but no
	 * scheduler structure holds is recorded; a CPU whose tree and local
	 * DSQ account for every queued task is not, so an empty ring is a
	 * result.
	 */
	if (missing > 0) {
		inf_snap_core(cpu, INF_CB_TICK, true);
		return;
	}

	now = cctx->last_disp_ns;
	if (depth > 0 && now && scx_bpf_now() - now > 5000000ULL)
		inf_snap_core(cpu, INF_CB_TICK, true);
}

static __noinline void inf_snap_selection(s32 cpu, inf_cpu_block_t *blk)
{
	struct inf_dispatch_snap *snap;
	struct inf_cfg		 *cfg;
	struct inf_cpu_ctx	 *cctx;
	u32			  key = (u32)cpu;
	u32			  i, n, reason;

	snap = bpf_map_lookup_elem(&dsnap_stor, &key);
	if (!snap)
		return;

	reason = blk->sel_reason;
	if (reason >= INF_SEL_REASONS)
		reason = 0;

	n = blk->sel_levels;
	if (n > INF_SEL_DEPTH_MAX)
		n = INF_SEL_DEPTH_MAX;

	snap->ts	 = bpf_ktime_get_ns();
	snap->cpu	 = (u64)cpu;
	snap->reason	 = blk->sel_reason;
	snap->cause	 = blk->sel_cause;
	snap->attempts	 = blk->sel_attempts;
	snap->nr_levels	 = n;
	snap->generation = 0;
	snap->depth	 = 0;

	cfg		 = inf_cfg();
	if (cfg)
		snap->generation = READ_ONCE(cfg->generation);

	cctx = inf_cpu_ctx(cpu);
	if (cctx && cctx->depth > 0)
		snap->depth = (u64)cctx->depth;

	/*
	 * What the core counts for this CPU. A dispatch runs on an idle
	 * CPU that has queued tasks, so the task that is running here
	 * contributes nothing: the idle task is not one of ours.
	 *
	 * A runnable @prev is the exception. The core keeps it counted on
	 * this runqueue and enqueues it only after ops.dispatch() returns,
	 * so it is outside the tree and outside the local DSQ while this
	 * record is taken. Subtracting it is what makes a nonzero
	 * core_missing mean a task in core custody: without the
	 * subtraction, the outgoing task alone fills the count and the
	 * record proves nothing.
	 */
	{
		struct rq *rq	    = scx_bpf_locked_rq();
		u64	   nr	    = 0;
		u64	   loc	    = 0;
		u64	   prev_run = 0;
		s64	   missing;

		if (rq) {
			nr  = rq->scx.nr_running;
			loc = rq->scx.local_dsq.nr;
		}
		/*
		 * The task the core switches out is rq->curr here, and it
		 * is still runnable when SCX_TASK_QUEUED is set: the core
		 * enqueues it only after this callback returns, so it
		 * counts on the runqueue while no queue of this scheduler
		 * holds it.
		 */
		if (rq && rq->curr && rq->curr != rq->idle &&
		    (rq->curr->scx.flags & SCX_TASK_QUEUED))
			prev_run = 1;
		snap->core_nr_running	 = nr;
		snap->core_local_nr	 = loc;
		snap->core_prev_runnable = prev_run;
		missing = (s64)nr - (s64)snap->depth - (s64)loc - (s64)prev_run;
		snap->core_missing = missing > 0 ? (u64)missing : 0;
	}

	snap->band_full	     = blk->band_full;
	snap->band_tail_node = blk->band_tail_node;
	snap->band_tail_null = blk->band_tail_null;

	__sync_fetch_and_add(&snap->reason_count[reason], 1);

	/*
	 * An empty root queue has nothing to descend into, so its record says
	 * only that the tree was empty. Every other failure keeps the queues
	 * it inspected.
	 */
	if (reason == INF_SEL_EMPTY && n <= 1)
		return;

	for (i = 0; i < INF_SEL_DEPTH_MAX && can_loop; i++) {
		struct inf_sel_level __arena *src;
		inf_group_entity_t	     *pe;
		u32			      is_group;
		s32			      id;

		if (i >= n)
			break;
		src		    = &blk->sel[i];

		snap->lvl[i].depth  = src->depth;
		snap->lvl[i].parent = src->parent;
		snap->lvl[i].vmin   = src->vmin;
		snap->lvl[i].scan   = src->scan;
		snap->lvl[i].child  = src->child;
		snap->lvl[i].pid    = src->pid;
		snap->lvl[i].flags  = src->flags;

		/*
		 * The queue of the level: its size, its frontier and the
		 * identity of its tree root and its head. The scan left the
		 * queue unlocked, so these fields are advisory, which is what
		 * the record is.
		 */
		pe = inf_entity(blk, src->parent);
		if (pe) {
			snap->lvl[i].nr	      = inf_queue_nr(&pe->children);
			snap->lvl[i].frontier = pe->frontier_q16;
			inf_child_identity(blk, pe->children.first, &id,
					   &is_group);
			snap->lvl[i].first = id;
			if (is_group)
				snap->lvl[i].flags |= INF_SEL_F_FIRST_GROUP;
			inf_child_identity(blk, pe->children.root, &id,
					   &is_group);
			snap->lvl[i].root = id;
			if (is_group)
				snap->lvl[i].flags |= INF_SEL_F_ROOT_GROUP;
			if (!pe->children.first)
				snap->lvl[i].flags |= INF_SEL_F_EMPTY;
		}

		/* The winning group of the level. */
		if (src->flags & INF_SEL_F_WIN_GROUP) {
			inf_group_entity_t *e = inf_entity(blk, src->child);

			if (e) {
				snap->lvl[i].v		= e->v_q16;
				snap->lvl[i].class	= e->class;
				snap->lvl[i].count	= e->count;
				snap->lvl[i].state	= e->state;
				snap->lvl[i].refs	= e->refs;
				snap->lvl[i].generation = e->generation;
			}
		}
	}
}

/*
 * Select the leaf task of this CPU's tree and hand it to the local DSQ.
 * The path of the task leaves the tree and is held by the reservation.
 *
 * The failure snapshot of the selection subtracts the task the core is
 * switching out: it is counted on this runqueue but is enqueued only after
 * this call returns.
 */
static __noinline bool inf_dispatch_tree(s32 cpu, struct inf_cpu_ctx *cctx)
{
	inf_cpu_block_t		*blk = inf_block(cpu);
	inf_group_entity_t	*leaf;
	struct inf_path __arena *path;
	struct task_struct	*p;
	task_ctx		*tctx = NULL;
	u32			 i;
	u32			 leaf_idx;
	int			 ret;
	bool			 stolen = false;

	if (!blk)
		return false;

	path = &blk->path;

	/*
	 * The local selection first. When the local tree has nothing, one
	 * steal brings a peer task into this tree. The stolen task is held
	 * in the destination leaf queue at this point, and the shared tail
	 * below removes it and hands it to the local DSQ. A kick of this
	 * CPU would not re-enter dispatch from here, so the handoff has to
	 * happen in this call.
	 */
	if (inf_select_leaf(blk, blk, &tctx)) {
		/*
		 * The parent of the selected task is the deepest entity on
		 * the path, not the first one: a task two cgroup levels
		 * below the root sits in the child queue of path->ent[1]. A
		 * task that is a direct child of the root cgroup has no
		 * group level on its path, and the root entity holds it.
		 */
		leaf_idx = path->depth > 0 ? path->ent[(path->depth - 1) &
						       (INF_MAX_LEVELS - 1)] :
					     0;
	} else {
		/*
		 * The local selection handed out nothing. Copy its scratch
		 * into the persistent snapshot before the steal overwrites
		 * it: a stall on this CPU is an idle CPU with tasks in core
		 * custody and no other record, because the exit snapshots run
		 * after the disable pass.
		 */
		/*
		 * The dispatch program is close to the verifier instruction
		 * budget, so the wider core record is taken from the tick and
		 * the selection record alone is written here.
		 */
		inf_snap_selection(cpu, blk);

		if (!inf_steal_one(cpu, cctx, &tctx, &leaf_idx)) {
			/*
			 * The tree reports runnable tasks through its depth,
			 * but the selection found none and the steal tiers
			 * had nothing either. The tree and the queues below
			 * it disagree, and every task in it is stranded
			 * until the watchdog fires.
			 */
			if (READ_ONCE(cctx->depth) > 0)
				INF_STAT_INC(disp_empty_lost);

			/*
			 * The record above is taken before the repair, so it
			 * states what the tree claimed at the failure. The
			 * depth then follows the root count, which is the one
			 * number that an admission and a removal both keep.
			 */
			inf_depth_sync(cpu);
			return false;
		}
		stolen = true;
	}

	leaf = inf_entity(blk, leaf_idx);
	if (!leaf)
		return false;

	if (!stolen && tctx->state != INF_ENTITY_RUNNABLE) {
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
	ret = inf_q_remove(&leaf->children, &tctx->qnode);
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
		if (inf_admit_on_cpu(p, tctx, cpu, INF_INS_NORMAL, false))
			INF_STAT_INC(lost_state_errors);
		bpf_task_release(p);
		return false;
	}

	tctx->state	 = INF_ENTITY_SELECTED;
	tctx->queued_cpu = -1;
	inf_depth_add(cpu, -1);

	/* The counts below the leaf follow the task. */
	inf_count_down(blk, leaf_idx);

	if (stolen) {
		/*
		 * The steal already built the path of the task on this CPU
		 * and committed the destination leaf gate. The frontier of
		 * the destination moved with that commit, so it is not
		 * applied a second time here.
		 */
		tctx->path_cpu = cpu;
	} else {
		/* The path of the task is held by the task. */
		tctx->path_depth = path->depth;
		tctx->path_cpu	 = cpu;
		if (tctx->path_depth > INF_MAX_LEVELS)
			tctx->path_depth = INF_MAX_LEVELS;
		for (i = 0; i < INF_MAX_LEVELS && can_loop; i++) {
			if (i >= tctx->path_depth)
				break;
			tctx->path_ent[i] = path->ent[i & (INF_MAX_LEVELS - 1)];
		}

		/* The frontier of every level follows the selection. */
		inf_apply_frontier(blk, path);
	}

	if ((p->flags & PF_EXITING) || tctx->state == INF_ENTITY_EXITING) {
		/*
		 * An exiting task in kernel custody is handed to the local
		 * DSQ. The core clears custody and the CPU runs the final
		 * exit.
		 */
		tctx->state	   = INF_ENTITY_EXITING;
		tctx->exit_pending = 0;
		tctx->queued_cpu   = -1;
		tctx->path_depth   = 0;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			INF_STAT_INC(lost_state_errors);
		} else {
			tctx->slice_ns = INF_SLOT_NS;
			if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, INF_SLOT_NS,
					       0))
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
		if (target >= 0 &&
		    !inf_admit_on_cpu(p, tctx, target, INF_INS_NORMAL, true)) {
			INF_STAT_INC(migrate_admits);
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

	/*
	 * The slot the task will get. The reservation itself opens in
	 * ops.running(), after the predecessor settled its own slot.
	 */
	tctx->slice_ns = inf_cpu_slot_ns(cpu);
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
			inf_requeue_path(tctx, INF_INS_TAIL);
			bpf_task_release(p);
			inf_queue_drop(&tctx->qnode);
			return false;
		}
	}

	if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, tctx->slice_ns, 0)) {
		/*
		 * The core refused the local insert. Put the path back
		 * instead of dropping a runnable task. The refusal is the
		 * submission result that the task record carries: the task
		 * is back in the tree, so the record names the submission,
		 * not the enqueue, as what happened.
		 */
		inf_trace(INF_TR_DSQ_REFUSED, tctx, INF_TR_WHERE(cpu, cpu), 0);
		INF_STAT_INC(disp_dsq_fail);
		tctx->last_dsq_ret = -EAGAIN;
		inf_requeue_path(tctx, INF_INS_TAIL);
		bpf_task_release(p);
		inf_queue_drop(&tctx->qnode);
		return false;
	}
	tctx->last_dsq_ret = 0;
	inf_trace(INF_TR_DSQ_OK, tctx, INF_TR_WHERE(cpu, cpu), 0);

	bpf_task_release(p);
	inf_queue_drop(&tctx->qnode);
	return true;
}

/*
 * The read-only peek of a peer tree, and the hypothetical destination
 * selection of a steal.
 *
 * The head of every queue on the path is the child with the lowest
 * service, so it is the band minimum of that queue. The band filter can
 * never exclude it. The peek removes nothing, takes no hold and changes
 * no key, no gate, no service and no frontier.
 */
static __noinline bool inf_steal_peek(inf_cpu_block_t *pblk,
				      inf_cpu_block_t *dblk, task_ctx **leaf)
{
	struct inf_path __arena *path  = &dblk->path;
	u32			 idx   = 0;
	u32			 level = 0;

	/*
	 * The counter of the descent lives in the arena, so the verifier
	 * sees an imprecise value and the states of the peek stay equal.
	 */
	dblk->counter[INF_COUNTER_PEEK] = 0;
	while (can_loop) {
		inf_group_entity_t *e = inf_entity(pblk, idx);
		scx_edq_node_t	   *hn;
		scx_edq_task_t	   *head;

		if (!e)
			return false;
		hn = e->children.first;
		if (!hn) {
			INF_STAT_INC(steal_peek_empty);
			return false;
		}
		head = inf_queue_node_task(hn);

		if (!inf_node_is_group(pblk, (u64)head)) {
			path->depth = level;
			*leaf	    = inf_task_from_qnode(head);
			return true;
		}

		if (dblk->counter[INF_COUNTER_PEEK] >= INF_MAX_LEVELS)
			return false;
		dblk->counter[INF_COUNTER_PEEK]++;
		path->ent[level & (INF_MAX_LEVELS - 1)] =
			inf_entity_index(pblk, (inf_group_entity_t *)head);
		idx = path->ent[level & (INF_MAX_LEVELS - 1)];
		level++;
	}

	return false;
}

/*
 * Steal the band winner of a peer tree, transactionally.
 *
 * The order is the one of specification section 4.3: a read-only
 * hypothetical selection, an affinity check, a compare-and-swap on the
 * single-owner handoff flag, the removal of the task from its source
 * queue, a revalidation of the destination, and an insertion at the
 * destination frontier. The destination gate advances only after the
 * insert commits. A refusal at any step restores the saved source record,
 * so a failed steal leaves the source level where it was. The source queue
 * lock is released before the destination queue lock is taken, so no two
 * queue locks are held at once.
 */
static __noinline bool inf_steal_from(s32 peer, s32 dst,
				      struct inf_cpu_ctx *dcctx, task_ctx **out,
				      u32 *leaf_out)
{
	inf_cpu_block_t	     *pblk = inf_block(peer);
	inf_cpu_block_t	     *dblk = inf_block(dst);
	inf_group_entity_t   *sleaf;
	inf_group_entity_t   *dleaf;
	struct inf_fault_ctl *fault;
	struct task_struct   *p;
	task_ctx	     *tctx = NULL;
	u64		      saved_v, saved_rem, saved_tie, tie = 0, cgrp_id;
	u32		      saved_cls, leaf_parent = 0, sleaf_idx, cls;
	int		      ret;

	if (!pblk || !dblk || pblk == dblk)
		return false;

	if (!inf_steal_peek(pblk, dblk, &tctx))
		return false;
	if (!tctx)
		return false;

	p = bpf_task_from_pid(tctx->pid);
	if (!p) {
		INF_STAT_INC(stale_skips);
		return false;
	}

	/* The task must be allowed on the destination CPU. */
	if (!inf_cpu_allowed(p, inf_cpu_topo(dst), dst)) {
		INF_STAT_INC(steal_affinity_refusals);
		bpf_task_release(p);
		return false;
	}

	if (tctx->dequeue_pending || tctx->exit_pending ||
	    tctx->state != INF_ENTITY_RUNNABLE || tctx->queued_cpu != peer) {
		INF_STAT_INC(steal_revalidate_refusals);
		bpf_task_release(p);
		return false;
	}

	INF_STAT_INC(steal_attempts);

	/* One writer owns the move. A lost race is a refusal. */
	inf_queue_hold(&tctx->qnode);
	if (cmpxchg(&tctx->moving, 0, 1)) {
		inf_queue_drop(&tctx->qnode);
		bpf_task_release(p);
		INF_STAT_INC(steal_owner_refusals);
		return false;
	}

	/*
	 * The source leaf. It is the deepest entity on the peeked path: the
	 * node sits in the child queue of path->ent[depth - 1]. A peer tree
	 * whose path has no group level holds the task in the root entity,
	 * so the index is 0.
	 */
	sleaf_idx = dblk->path.depth > 0 ?
			    dblk->path.ent[(dblk->path.depth - 1) &
					   (INF_MAX_LEVELS - 1)] :
			    0;
	sleaf	  = inf_entity(pblk, sleaf_idx);
	if (!sleaf) {
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		bpf_task_release(p);
		INF_STAT_INC(steal_failures);
		return false;
	}

	/* The source record is saved before the task leaves the source. */
	saved_v	  = tctx->v_q16;
	saved_rem = tctx->rem;
	saved_cls = tctx->class;
	saved_tie = tctx->tie;

	/* The task leaves the source queue. */
	ret = inf_q_remove(&sleaf->children, &tctx->qnode);
	if (ret) {
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		bpf_task_release(p);
		INF_STAT_INC(steal_failures);
		return false;
	}
	/*
	 * The task leaves the source queue and its counts follow. The
	 * removal runs on this CPU while the source CPU may admit, so the
	 * order is queue first and counts second; the source selection
	 * treats an empty queue with a count as a task in transit.
	 */
	tctx->state	 = INF_ENTITY_HANDOFF;
	tctx->queued_cpu = -1;
	inf_count_down(pblk, sleaf_idx);
	inf_depth_add(peer, -1);

	/*
	 * The destination is revalidated after the source removal, because
	 * the affinity mask can change while the task moves. A refusal here
	 * restores the source record.
	 */
	fault = inf_fault();
	if (!fault)
		INF_STAT_INC(steal_fault_missing);
	if (!inf_cpu_allowed(p, inf_cpu_topo(dst), dst)) {
		INF_STAT_INC(steal_revalidate_refusals);
		goto restore;
	}
	if (fault && inf_fault_take(&fault->steal_dest_refuse)) {
		INF_STAT_INC(steal_fault_taken);
		INF_STAT_INC(steal_revalidate_refusals);
		goto restore;
	}
	if (tctx->dequeue_pending || tctx->exit_pending) {
		INF_STAT_INC(steal_revalidate_refusals);
		goto restore;
	}

	leaf_parent = inf_resolve_leaf(dblk, inf_task_cgroup(p), &cgrp_id);
#if INF_BISECT_VARIANT == 4
	leaf_parent = 0;
#endif
	dleaf = inf_entity(dblk, leaf_parent);
	if (!dleaf) {
		INF_STAT_INC(steal_revalidate_refusals);
		goto restore;
	}

	/*
	 * The destination record. The gate verdict is read, not committed:
	 * the gate and the tie advance only after the insert succeeded.
	 */
	cls	    = inf_gate_peek(dleaf, INF_INS_NORMAL, &tie);
	tctx->v_q16 = dleaf->frontier_q16;
	tctx->rem   = 0;
	tctx->class = cls;
	tctx->tie   = tie;
	if (fault && inf_fault_take(&fault->steal_insert_refuse)) {
		INF_STAT_INC(steal_insert_refusals);
		goto restore;
	}
	if (inf_q_insert(&dleaf->children, &tctx->qnode, tctx->v_q16)) {
		INF_STAT_INC(steal_insert_refusals);
		goto restore;
	}

	/* The steal committed: the gate steps, then the task moves. */
	inf_gate_commit(dleaf, INF_INS_NORMAL);
	tctx->state = INF_ENTITY_RUNNABLE;
	inf_task_attach(tctx, dblk, dst, leaf_parent);
	tctx->cgrp_id	 = cgrp_id;
	tctx->path_cpu	 = dst;
	tctx->queued_cpu = dst;

	/* The path of the task on the destination CPU. */
	tctx->path_depth = 0;
	{
		u32 idx = leaf_parent;
		u32 level;

		for (level = 0; level < INF_MAX_LEVELS && idx != 0 && can_loop;
		     level++) {
			inf_group_entity_t *e = inf_entity(dblk, idx);

			if (!e)
				break;
			tctx->path_ent[tctx->path_depth] = idx;
			tctx->path_depth++;
			idx = e->parent_idx;
		}
	}

	inf_count_up(dblk, leaf_parent, INF_INS_NORMAL);
	inf_depth_add(dst, 1);
	INF_STAT_INC(steals);
	INF_STAT_INC(disp_steal);
	inf_trace(INF_TR_STEAL, tctx, INF_TR_WHERE(peer, dst), 0);

	*out	     = tctx;
	*leaf_out    = leaf_parent;
	tctx->moving = 0;
	inf_queue_drop(&tctx->qnode);
	bpf_task_release(p);
	return true;

restore:
	/*
	 * The destination refused the task. The source record goes back and
	 * the node re-enters the source queue with its old service and tie.
	 * The destination leaf gate never advanced, and the source ancestors
	 * are re-linked with their own retained record.
	 */
	tctx->v_q16	 = saved_v;
	tctx->rem	 = saved_rem;
	tctx->class	 = saved_cls;
	tctx->tie	 = saved_tie;
	tctx->state	 = INF_ENTITY_RUNNABLE;
	tctx->queued_cpu = peer;
	if (inf_q_insert(&sleaf->children, &tctx->qnode, saved_v)) {
		inf_queue_unlink(&tctx->qnode);
		if (inf_q_insert(&sleaf->children, &tctx->qnode, saved_v))
			INF_STAT_INC(lost_state_errors);
	}
	inf_restore_up(pblk, sleaf_idx);
	inf_depth_add(peer, 1);
	/*
	 * The task is back in the source tree. The source CPU may be idle,
	 * so it needs a kick or the task waits for an unrelated wakeup.
	 */
	scx_bpf_kick_cpu(peer, SCX_KICK_IDLE);
	tctx->moving = 0;
	INF_STAT_INC(steal_failures);
	INF_STAT_INC(steal_rollbacks);
	inf_trace(INF_TR_STEAL_SKIP, tctx, INF_TR_WHERE(peer, dst), -1);
	inf_queue_drop(&tctx->qnode);
	bpf_task_release(p);
	return false;
}

/*
 * The local-work oracle of the steal decision. A remote spill is allowed
 * only when this CPU's own tree holds no dispatchable entity. The depth
 * counts the tasks that are allowed on this CPU and not throttled, so a
 * local task that the last selection could not hand out blocks the node
 * tier. An affinity-limited task and a throttled task are not in this
 * tree, so they do not block it.
 */
static __noinline bool inf_local_work(s32 cpu)
{
	struct inf_cpu_ctx *cctx = inf_cpu_ctx(cpu);

	return cctx && READ_ONCE(cctx->depth) > 0;
}

/*
 * One steal tier: at most eight eligible peers, starting at the cursor
 * and wrapping. The cursor advances past every examined peer, so the next
 * dispatch starts where this one stopped.
 */
static __noinline bool inf_steal_tier(s32 cpu, u32 llc, u32 node, u32 tier,
				      u32 *cursor, struct inf_cpu_ctx *dcctx,
				      task_ctx **out, u32 *leaf_out)
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

		if (inf_steal_from((s32)peer, cpu, dcctx, out, leaf_out)) {
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
 * One steal attempt for this CPU. The same-LLC tier always runs. The
 * node tier is the remote spill, and it runs only when the local tree
 * holds no dispatchable task that is allowed on this CPU. Returns true
 * when one task entered this CPU's tree.
 */
static __noinline bool inf_steal_one(s32 cpu, struct inf_cpu_ctx *cctx,
				     task_ctx **out, u32 *leaf_out)
{
	struct inf_cpu_topo *lt = inf_cpu_topo(cpu);

#if INF_BISECT_VARIANT == 2
	/* Variant 2: the local tree only. */
	return false;
#endif
	if (!lt || !lt->online)
		return false;
	if (inf_steal_tier(cpu, lt->llc_id, lt->node_id, INF_STEAL_LLC,
			   &cctx->steal_llc_cursor, cctx, out, leaf_out))
		return true;
	if (inf_local_work(cpu)) {
		INF_STAT_INC(steal_remote_refusals);
		return false;
	}
	return inf_steal_tier(cpu, lt->llc_id, lt->node_id, INF_STEAL_NODE,
			      &cctx->steal_node_cursor, cctx, out, leaf_out);
}

/*
 * Dispatch: the local tree first, then same-LLC peers, then same-NUMA
 * peers outside the local LLC. If nothing is runnable, renew the previous
 * task in place when its slice expired.
 */
void BPF_STRUCT_OPS(infinity_dispatch, s32 cpu, struct task_struct *prev)
{
	struct inf_cpu_ctx *cctx;
	task_ctx	   *tctx = NULL;

	TOUCH_ARENA();

	cctx = inf_cpu_ctx(cpu);
	if (!cctx)
		return;

	/* Re-enqueue backlogged tasks of cgroups that got time again. */
	if (inf_cpu_bw_enabled())
		scx_cgroup_ctl_reenqueue();

	/*
	 * The tree selection runs the steal itself when the local tree has
	 * nothing to hand out, so the stolen task is selected again in the
	 * same dispatch.
	 */
	cctx->disp_calls++;

	if (inf_dispatch_tree(cpu, cctx))
		return;

	/*
	 * The tree is empty and the previous task is still runnable with
	 * no slice left. Renew it in place instead of waiting for a round
	 * trip through enqueue.
	 */
	if (prev && !READ_ONCE(prev->scx.slice)) {
		tctx = inf_task_ctx(prev);
		/*
		 * Only a slot this context holds may be renewed. Renewing a
		 * task it does not hold would keep that task on the core's
		 * local DSQ without a tree entry, and the dispatch would not
		 * run again while the local DSQ stays occupied.
		 */
		if (tctx && (tctx->state == INF_ENTITY_SELECTED ||
			     tctx->state == INF_ENTITY_RUNNING)) {
			scx_bpf_task_set_slice(prev, INF_SLOT_NS);
			INF_STAT_INC(disp_renew);
		} else {
			INF_STAT_INC(disp_renew_unowned);
		}
	}

	cctx->disp_empty++;
	cctx->last_disp_ns = scx_bpf_now();
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
	inf_cb_note(INF_CB_DEQUEUE);

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	{
		struct inf_cpu_ctx *cc =
			inf_cpu_ctx(bpf_get_smp_processor_id());

		if (cc)
			cc->deq_calls++;
	}

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
				  INF_TR_WHERE(tctx->queued_cpu, -1),
				  deq_flags);
			return;
		}
		/*
		 * The reservation closes before the task leaves, so a sleep
		 * or a property change cannot leave an open slot behind.
		 */
		inf_settle_slot(p, tctx, inf_slot_event(tctx),
				inf_resv_local(inf_cpu_ctx(tctx->path_cpu)));
		inf_task_leave(tctx);
		inf_trace(INF_TR_DEQ_QUEUED, tctx,
			  INF_TR_WHERE(tctx->queued_cpu, -1), deq_flags);
	} else {
		inf_trace(INF_TR_DEQ_END, tctx, INF_TR_WHERE(-1, -1),
			  deq_flags);
	}

	/*
	 * SCX_DEQ_CORE_SCHED_EXEC means the core ran a task that was still
	 * queued. It stays runnable, so it moves to RUNNING. A sleep or a
	 * property change ends the runnable period.
	 */
	if (core_exec) {
		tctx->state = INF_ENTITY_RUNNING;
	} else if (ended) {
		if (tctx->state != INF_ENTITY_EXITING) {
			tctx->state	    = INF_ENTITY_INACTIVE;
		}
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
	inf_cb_note(INF_CB_QUIESCENT);

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	{
		struct inf_cpu_ctx *cc =
			inf_cpu_ctx(bpf_get_smp_processor_id());

		if (cc)
			cc->q_calls++;
	}

	if ((deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_SCHED_CHANGE)) &&
	    tctx->state != INF_ENTITY_RUNNABLE &&
	    tctx->state != INF_ENTITY_SELECTED &&
	    tctx->state != INF_ENTITY_RUNNING) {
		INF_STAT_INC(q_unowned);
		inf_trace(INF_TR_QUIESCENT, tctx, INF_TR_WHERE(-1, -1),
			  deq_flags);
	}

	if (deq_flags & SCX_DEQ_SLEEP)
		INF_STAT_INC(q_sleep);
	else if (deq_flags & SCX_DEQ_SCHED_CHANGE)
		INF_STAT_INC(q_sched_change);
	else
		INF_STAT_INC(q_keep);

	if (!(deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_SCHED_CHANGE)))
		return;

	if (tctx->state == INF_ENTITY_RUNNABLE) {
		/*
		 * A queued task: the runnable period ends and the task leaves
		 * the tree with its leaf and ancestor counts.
		 */
		inf_trace(INF_TR_Q_LEAVE, tctx,
			  INF_TR_WHERE(tctx->queued_cpu, tctx->path_cpu),
			  deq_flags);
		inf_settle_slot(p, tctx, inf_slot_event(tctx), false);
		inf_task_leave(tctx);
		return;
	}

	if (tctx->state == INF_ENTITY_SELECTED ||
	    tctx->state == INF_ENTITY_RUNNING) {
		/*
		 * The task is dispatched or running, so it holds a path and no
		 * queue membership. A dequeue of it is not the end of that
		 * path: the core can restore the current task with
		 * ENQUEUE_RESTORE, and scx_do_enqueue_task() puts it back on the
		 * local DSQ without an ops.enqueue() (kernel/sched/ext/ext.c,
		 * the `sticky_cpu == cpu_of(rq)` branch). ops.running() then
		 * follows this callback with no transition in between. The slot
		 * is settled here and the path is kept, so the next start
		 * charges the same ancestors instead of running as a task the
		 * tree has released. The path is released by the next enqueue,
		 * by the exit or by a cgroup move.
		 */
		inf_trace(INF_TR_Q_LEAVE, tctx,
			  INF_TR_WHERE(tctx->queued_cpu, tctx->path_cpu),
			  deq_flags);
		inf_settle_slot(p, tctx, inf_slot_event(tctx), false);
	}
}

/*
 * A nice-weight change. The task keeps its service value and re-enters
 * through the normal gate with the new weight.
 */
void BPF_STRUCT_OPS(infinity_set_weight, struct task_struct *p, u32 weight)
{
	task_ctx *tctx;
	s32	  cpu;
	u32	  new_weight;

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

	/*
	 * A running or dispatched task settles the current slot with the
	 * old weight and observes the new one at its next slot. The residue
	 * is flushed only when the new weight takes effect.
	 */
	if (tctx->state == INF_ENTITY_SELECTED ||
	    tctx->state == INF_ENTITY_RUNNING) {
		tctx->pending_weight   = new_weight;
		tctx->reweight_pending = 1;
		tctx->base_weight      = new_weight;
		INF_STAT_INC(epoch_deferred);
		return;
	}

	/* The residue is flushed under the old weight. */
	tctx->rem	       = 0;
	tctx->pending_weight   = 0;
	tctx->reweight_pending = 0;
	tctx->latched_weight   = new_weight;
	tctx->base_weight      = new_weight;

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
	if (inf_admit_on_cpu(p, tctx, cpu, INF_INS_NORMAL, false))
		INF_STAT_INC(lost_state_errors);
	inf_trace(INF_TR_REWEIGHT, tctx, INF_TR_WHERE(cpu, -1), 0);
}

/*
 * True when @v is inside the service band of the queue of @parent. The
 * head of the queue carries the minimum service, so it is the band
 * minimum. An empty queue has no band, and the caller is refused.
 */
static __always_inline bool
inf_entity_in_band(inf_cpu_block_t *blk, inf_group_entity_t *parent, u64 v)
{
	u64 vmin;

	if (!inf_queue_head_v(blk, parent, &vmin))
		return false;
	return !!inf_in_band_mask(v, vmin);
}

/*
 * Move a runnable queued target to the head class of its own queue. The
 * target must be inside its current service band, and every group entity
 * on its path must be inside the band of its own parent queue. The
 * promotion takes the head class with the newest tie and does not advance
 * a gate, so the 7:1 ratio of the normal arrivals is unchanged. A target
 * that is running, dispatched, throttled, exiting or not queued is
 * refused. A target on another CPU stays on that CPU.
 */
static __noinline bool inf_yield_to(struct task_struct *from,
				    struct task_struct *to)
{
	inf_cpu_block_t	     *blk;
	inf_group_entity_t   *parent;
	struct inf_fault_ctl *fault;
	task_ctx	     *tctx;
	u64		      saved_v, saved_rem, saved_tie, tie;
	u32		      saved_cls;
	s32		      tcpu;
	u32		      level;
	int		      ret;

	INF_STAT_INC(yield_to_checks);

	if (!to || to == from || (to->flags & PF_EXITING)) {
		INF_STAT_INC(yield_to_refuse_state);
		return false;
	}
	if (scx_bpf_task_running(to)) {
		INF_STAT_INC(yield_to_refuse_running);
		return false;
	}

	tctx = inf_task_ctx(to);
	if (!tctx || tctx->state != INF_ENTITY_RUNNABLE ||
	    tctx->queued_cpu < 0) {
		INF_STAT_INC(yield_to_refuse_state);
		return false;
	}

	tcpu = tctx->queued_cpu;
	/* A task in a sched_ext local DSQ is not in our tree. */
	if (to == __COMPAT_scx_bpf_cpu_curr(tcpu)) {
		INF_STAT_INC(yield_to_refuse_running);
		return false;
	}

	blk = inf_block(tcpu);
	if (!blk) {
		INF_STAT_INC(yield_to_refuse_state);
		return false;
	}
	parent = inf_entity(blk, (u32)tctx->parent_idx);
	if (!parent) {
		INF_STAT_INC(yield_to_refuse_state);
		return false;
	}

	/*
	 * The band of the target inside its own leaf queue, then the band
	 * of every group entity on its path inside the parent queue of that
	 * entity. The reads are advisory: a queue that changes can only make
	 * the check refuse.
	 */
	if (!inf_entity_in_band(blk, parent, tctx->v_q16)) {
		INF_STAT_INC(yield_to_refuse_band);
		return false;
	}

	/*
	 * The ancestors of the target. The leaf parent competes in the
	 * queue of the root, its parent in the next queue, and so on. Each
	 * entity must be inside the band of the queue that holds it.
	 */
	{
		u32 idx = (u32)tctx->parent_idx;

		for (level = 0; level < INF_MAX_LEVELS && idx != 0 && can_loop;
		     level++) {
			inf_group_entity_t *e = inf_entity(blk, idx);
			inf_group_entity_t *par;

			if (!e)
				break;
			par = inf_entity(blk, e->parent_idx);
			if (!par) {
				INF_STAT_INC(yield_to_refuse_band);
				return false;
			}
			if (!inf_entity_in_band(blk, par, e->v_q16)) {
				INF_STAT_INC(yield_to_refuse_band);
				return false;
			}
			idx = e->parent_idx;
		}
	}

	fault = inf_fault();
	if (fault && inf_fault_take(&fault->yield_probe_band_refuse)) {
		INF_STAT_INC(yield_to_refuse_band);
		return false;
	}

	/* One writer owns the node. A lost race is a refusal, not a move. */
	inf_queue_hold(&tctx->qnode);
	if (cmpxchg(&tctx->moving, 0, 1)) {
		inf_queue_drop(&tctx->qnode);
		INF_STAT_INC(yield_to_refuse_state);
		return false;
	}

	saved_v	  = tctx->v_q16;
	saved_rem = tctx->rem;
	saved_cls = tctx->class;
	saved_tie = tctx->tie;

	ret	  = inf_q_remove(&parent->children, &tctx->qnode);
	if (ret) {
		tctx->moving = 0;
		inf_queue_drop(&tctx->qnode);
		INF_STAT_INC(yield_to_refuse_state);
		return false;
	}

	/*
	 * The head class with the newest tie. The gate does not advance, so
	 * the 7:1 ratio of the normal arrivals is unchanged. The tie steps
	 * only after the insert commits.
	 */
	tie	    = READ_ONCE(parent->tie_seq);
	tctx->class = INF_CLASS_HEAD;
	tctx->tie   = tie;
	tctx->v_q16 = inf_service_max(tctx->v_q16, parent->frontier_q16);
	if ((fault && inf_fault_take(&fault->yield_insert_refuse)) ||
	    inf_q_insert(&parent->children, &tctx->qnode, tctx->v_q16)) {
		/* Put the task back with its saved record. */
		tctx->v_q16 = saved_v;
		tctx->rem   = saved_rem;
		tctx->class = saved_cls;
		tctx->tie   = saved_tie;
		/*
		 * The task never left the ancestry of this queue, so the
		 * ancestor counts are unchanged and no count-up follows.
		 */
		if (inf_q_insert(&parent->children, &tctx->qnode, saved_v)) {
			inf_queue_unlink(&tctx->qnode);
			if (inf_q_insert(&parent->children, &tctx->qnode,
					 saved_v)) {
				tctx->state	 = INF_ENTITY_INACTIVE;
				tctx->queued_cpu = -1;
				INF_STAT_INC(lost_state_errors);
			}
		}
		tctx->moving = 0;
		INF_STAT_INC(yield_to_insert_fail);
		inf_queue_drop(&tctx->qnode);
		return false;
	}

	__sync_fetch_and_add(&parent->tie_seq, 1);
	tctx->moving = 0;
	INF_STAT_INC(yield_to_moves);
	inf_trace(INF_TR_YIELD_TO, tctx, INF_TR_WHERE(tcpu, tcpu), 0);
	inf_queue_drop(&tctx->qnode);
	return true;
}

/*
 * A synthetic yield-to target for the controlled-refusal test. The probe
 * runs only when user space arms it, and it uses a real queued or running
 * task, so the tested path is the production one.
 */
static __noinline struct task_struct *
inf_probe_target(struct inf_fault_ctl *fault)
{
	inf_cpu_block_t	   *blk;
	inf_group_entity_t *e;
	scx_edq_node_t	   *n;
	task_ctx	   *tctx;
	s32		    cpu;
	u32		    ncpu, level;

	cpu  = bpf_get_smp_processor_id();
	ncpu = inf_nr_cpu_ids();

	if (inf_fault_take(&fault->yield_probe_running)) {
		s32		    other = cpu + 1 < (s32)ncpu ? cpu + 1 : 0;
		struct task_struct *cur;

		if (other == cpu)
			return NULL;
		cur = __COMPAT_scx_bpf_cpu_curr(other);
		if (!cur)
			return NULL;
		return bpf_task_from_pid(cur->pid);
	}

	blk = inf_block(cpu);
	if (!blk)
		return NULL;
	e = inf_entity(blk, 0);
	if (!e)
		return NULL;
	n = e->children.first;
	for (level = 0; n && level <= INF_MAX_LEVELS && can_loop; level++) {
		scx_edq_task_t *node = inf_queue_node_task(n);

		if (!inf_node_is_group(blk, (u64)node)) {
			tctx = inf_task_from_qnode(node);
			return tctx ? bpf_task_from_pid(tctx->pid) : NULL;
		}
		e = (inf_group_entity_t *)node;
		n = e->children.first;
	}
	return NULL;
}

bool BPF_STRUCT_OPS(infinity_yield, struct task_struct *from,
		    struct task_struct *to)
{
	struct inf_fault_ctl *fault;
	task_ctx	     *tctx;
	bool		      moved = false;

	TOUCH_ARENA();
	inf_cb_note(INF_CB_YIELD);

	if (!from)
		return false;

	/* Yield forfeits the remaining slice; the core re-enqueues. */
	scx_bpf_task_set_slice(from, 0);
	tctx = inf_task_ctx(from);
	if (tctx) {
		struct inf_cpu_ctx *cctx = inf_resv_ctx(tctx);

		tctx->yielded		 = 1;
		/*
		 * The reservation pays for its slot even when the task stops
		 * early. The settle debits only the difference to the policy
		 * ledger, and cpu.max still sees the actual runtime.
		 */
		if (cctx)
			cctx->resv.flags |= INF_RESV_YIELD;
	}

	if (to && to != from)
		moved = inf_yield_to(from, to);

	/*
	 * The controlled-refusal probe. It adds a real promotion or a real
	 * refusal to a plain yield, and it runs only when armed.
	 */
	fault = inf_fault();
	if (!to && fault && inf_fault_take(&fault->yield_probe)) {
		struct task_struct *probe = inf_probe_target(fault);

		if (probe) {
			moved = inf_yield_to(from, probe) || moved;
			bpf_task_release(probe);
		}
	}

	INF_STAT_INC(yields);

	return moved;
}

void BPF_STRUCT_OPS(infinity_running, struct task_struct *p)
{
	task_ctx	   *tctx;
	struct inf_cpu_ctx *cctx;
	s32		    cpu;

	TOUCH_ARENA();
	inf_cb_note(INF_CB_RUNNING);

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	cpu  = bpf_get_smp_processor_id();
	cctx = inf_cpu_ctx(cpu);

	if (cctx)
		cctx->run_calls++;

	/*
	 * Two starts reach this callback without a tree admission, and both
	 * run for real:
	 *
	 * - A restored current task. The core dequeues a task and restores it
	 *   with ENQUEUE_RESTORE, and scx_do_enqueue_task() takes its
	 *   `sticky_cpu == cpu_of(rq)` branch to `local_norefill`
	 *   (kernel/sched/ext/ext.c), which puts the task back on the local
	 *   DSQ without calling ops.enqueue(). No callback refreshes the
	 *   state of such a task between the dequeue and this start, so it is
	 *   still RUNNABLE or INACTIVE here.
	 * - An exit hand-back. ops.enqueue() hands a task that is PF_EXITING
	 *   to the local DSQ with state EXITING, and the core runs it.
	 *
	 * Both take the slot of the CPU they run on. They used to return
	 * before inf_resv_open() because the state was not SELECTED, so no
	 * slot was open for them, every start was counted as unowned and the
	 * settle of the following stop charged nothing. The tree state is
	 * kept for the exit hand-back, which is not a queue entity.
	 */
	if (tctx->state != INF_ENTITY_SELECTED &&
	    tctx->state != INF_ENTITY_RUNNING) {
		INF_STAT_INC(run_unowned);
		if (tctx->state == INF_ENTITY_EXITING)
			INF_STAT_INC(run_exit_handoff);
		inf_trace(INF_TR_RUN_START, tctx,
			  INF_TR_WHERE(tctx->path_cpu, tctx->queued_cpu), 0);
	}

	if (cctx) {
		struct inf_stats *st = inf_stats();

		if (st) {
			u32 si = (tctx->state & 7) |
				 (tctx->queued_cpu >= 0 ? 8 : 0);

			__sync_fetch_and_add(&st->run_state[si], 1);
		}
	}

	tctx->last_running_ns = scx_bpf_now();

	/*
	 * The task runs, so it is running. A task that keeps a path is the
	 * ordinary case; an exit hand-back keeps EXITING because it is not a
	 * queue entity and no other callback may treat it as one.
	 */
	if (tctx->state != INF_ENTITY_EXITING)
		tctx->state = INF_ENTITY_RUNNING;

	if (!cctx)
		return;

	/*
	 * The reservation of the slot opens here, not at the dispatch.
	 *
	 * The core calls ops.stopping() for the outgoing task before
	 * set_next_task() of this one, so a reservation opened at the
	 * dispatch would take the per-CPU slot before the predecessor
	 * settled its own runtime, and that runtime would be lost. Opening
	 * the reservation when the task actually starts keeps the slot free
	 * for the settle of the task that is leaving.
	 *
	 * The slot belongs to the CPU the task runs on. The path of the task
	 * and the latched weights come from the task context, so the dispatch
	 * is the only place that sets them.
	 */
	inf_resv_reclaim(cctx, tctx);
	inf_resv_open(cctx, tctx, cpu);

	cctx->resv.start_now = tctx->last_running_ns;
	cctx->resv.flags |= INF_RESV_RUNNING;
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
	inf_cb_note(INF_CB_TICK);

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	{
		struct inf_cpu_ctx *cc =
			inf_cpu_ctx(bpf_get_smp_processor_id());

		if (cc) {
			cc->tick_calls++;
			inf_snap_core_tick(bpf_get_smp_processor_id(), cc);
		}
	}

	if (tctx->state != INF_ENTITY_RUNNING &&
	    tctx->state != INF_ENTITY_SELECTED)
		return;

	cctx = inf_resv_ctx(tctx);
	if (!cctx)
		return;

	/*
	 * A zero slice means the core slice expired before this tick. The
	 * task leaves through the leaf expiry row. A live slice means the
	 * slot ended normally, which is the post-slot ancestor requeue.
	 */
	event = READ_ONCE(p->scx.slice) ? INF_EV_POST_SLOT : INF_EV_EXPIRY;
	tctx->pending_event = event;

	local		    = inf_resv_local(cctx);

	/*
	 * One tick is one service slot. The local interval between two
	 * ticks of this CPU seeds the measured slot that the next dispatch
	 * reserves.
	 */
	inf_tick_measure(cctx, scx_bpf_now(), local);
	INF_STAT_INC(tick_slots);

	/*
	 * The settle charges the service of the path and the actual runtime
	 * of the slot. A remote tick counts the reserved slot.
	 *
	 * Bisection variant 3 has no reservation: the charge is taken at the
	 * stop, so the tick only ends the slot.
	 */
#if INF_BISECT_VARIANT != 3
	inf_settle_slot(p, tctx, event, local);
#endif

#if INF_BISECT_VARIANT != 5
	/* The slot ends here. Variant 5 lets the core slice expire instead. */
	scx_bpf_task_set_slice(p, 0);
#endif
}

/*
 * A running task stops being the current task. The open reservation is
 * settled here so a preemption, a migration or a slice expiry that the
 * tick did not see still charges the actual runtime exactly once.
 * cpu.max is charged through the settle only.
 */
void BPF_STRUCT_OPS(infinity_stopping, struct task_struct *p, bool runnable)
{
	task_ctx *tctx;

	TOUCH_ARENA();
	inf_cb_note(INF_CB_STOPPING);

	tctx = inf_task_ctx(p);
	if (!tctx)
		return;

	{
		struct inf_cpu_ctx *cc =
			inf_cpu_ctx(bpf_get_smp_processor_id());

		if (cc)
			cc->stop_calls++;
	}

	if (tctx->state != INF_ENTITY_SELECTED &&
	    tctx->state != INF_ENTITY_RUNNING) {
		INF_STAT_INC(stop_unowned);
		if (tctx->state == INF_ENTITY_EXITING)
			INF_STAT_INC(stop_exit_handoff);
		inf_trace(INF_TR_STOPPING, tctx,
			  INF_TR_WHERE(tctx->path_cpu, tctx->queued_cpu),
			  runnable ? 1 : 0);
	}

	{
		struct inf_stats *st = inf_stats();

		if (st) {
			u32 si = (tctx->state & 7) |
				 (tctx->queued_cpu >= 0 ? 8 : 0);

			__sync_fetch_and_add(&st->stop_state[si], 1);
		}
	}

	/*
	 * Settle the slot of this task, whichever CPU opened it, and only
	 * that slot. inf_settle_slot() finds the reservation by owner
	 * identity and returns when the task holds none, so a stop can no
	 * longer settle a slot that another task opened on this CPU.
	 */
	inf_settle_slot(p, tctx, inf_slot_event(tctx), false);
	INF_STAT_INC(resv_stop);

	/*
	 * The slot ends when the task stops.
	 *
	 * The core keeps a task that stops with a live slice on its local DSQ
	 * and re-picks it from there. A task in a local DSQ is served before
	 * ops.dispatch() runs, so a task that keeps a live slice across stops
	 * hides the whole tree of its CPU: the dispatch is never called while
	 * the local DSQ holds one task. A task the core re-queues itself
	 * without ops.enqueue() comes back into our custody only through the
	 * enqueue path, so leaving it with a live slice also keeps it out of
	 * the tree for good.
	 *
	 * Ending the slice here sends every stopped task back through
	 * ops.enqueue(), which either re-enters it into the tree or admits it
	 * anew. The CPU then reaches ops.dispatch() on the same scheduling
	 * pass. The tick ends a slot at its end and the yield and the
	 * preemption events keep their own requeue mode; only a stop that no
	 * event described arrives here with a live slice.
	 */
	if (scx_bpf_task_set_slice(p, 0))
		INF_STAT_INC(slot_end_stop);
	else
		INF_STAT_INC(stop_slice_refused);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(infinity_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	task_ctx	     *tctx;
	struct inf_task_pool *pool;
	bool		      fresh = false;
	u64		      live;
	int		      i;

	(void)args;

	TOUCH_ARENA();

	pool = inf_task_pool();

	/*
	 * One context per task for the whole task lifetime. init_task can run
	 * again for a task that already has a context, for example on a
	 * re-registration. Allocating a second context would orphan the
	 * first one in the arena pool for as long as the scheduler runs, so
	 * the live context is reused and re-seeded instead.
	 */
	tctx = inf_task_ctx(p);
	if (tctx) {
		if (pool)
			__sync_fetch_and_add(&pool->reinits, 1);
	} else {
		/* The task pool is bounded. A full pool fails the task. */
		if (pool && READ_ONCE(pool->live) >= INF_TASKS_MAX) {
			__sync_fetch_and_add(&pool->pool_full, 1);
			return -ENOMEM;
		}

		tctx = inf_task_ctx_alloc(p);
		if (!tctx) {
			if (pool)
				__sync_fetch_and_add(&pool->alloc_fail, 1);
			return -ENOMEM;
		}
		fresh = true;
		if (pool) {
			live = __sync_fetch_and_add(&pool->live, 1) + 1;
			__sync_fetch_and_add(&pool->inits, 1);
			if (live > READ_ONCE(pool->peak))
				WRITE_ONCE(pool->peak, live);
		}
	}

	/* Zero the whole context, then seed the live fields. */
	bpf_for(i, 0, (int)sizeof(*tctx))
	{
		((char __arena *)tctx)[i] = 0;
	}

	/* The queue node starts detached with a zero hold count. */
	if (inf_queue_node_init(&tctx->qnode)) {
		scx_task_free_rcu(p);
		if (fresh && pool)
			__sync_fetch_and_add(&pool->live, -1);
		return -EINVAL;
	}

	tctx->base_weight      = p->scx.weight ? p->scx.weight : 1;
	tctx->latched_weight   = inf_task_weight(p);
	tctx->pending_weight   = 0;
	tctx->slice_ns	       = 0;
	tctx->last_running_ns  = scx_bpf_now();
	tctx->epoch	       = scx_cgroup_ctl_epoch();
	tctx->queued_cpu       = -1;
	tctx->path_cpu	       = -1;
	tctx->cgrp_cpu	       = -1;
	tctx->path_depth       = 0;
	tctx->state	       = INF_ENTITY_INACTIVE;
	tctx->moving	       = 0;
	tctx->reweight_pending = 0;
	tctx->dequeue_pending  = 0;
	tctx->exit_pending     = 0;
	tctx->joined	       = 0;
	tctx->yielded	       = 0;
	tctx->preempted	       = 0;
	tctx->wake_fork	       = 0;
	tctx->idle	       = 0;
	tctx->pending_event    = INF_EV_NONE;
	tctx->pid	       = p->pid;
	return 0;
}

s32 BPF_STRUCT_OPS(infinity_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	task_ctx	     *tctx;
	struct inf_task_pool *pool;
	int		      ret;

	(void)args;

	TOUCH_ARENA();

	pool = inf_task_pool();

	tctx = inf_task_ctx(p);
	if (!tctx) {
		if (pool)
			__sync_fetch_and_add(&pool->no_ctx, 1);
		scx_task_free_rcu(p);
		return 0;
	}

	/* Settle the open slot before the path is released. */
	inf_settle_slot(p, tctx, inf_slot_event(tctx),
			inf_resv_local(inf_cpu_ctx(tctx->path_cpu)));
	INF_STAT_INC(resv_exit);

	/*
	 * Record the exit before the context is freed, so the ring still
	 * names the last transition of a task that died.
	 */
	inf_trace(INF_TR_EXIT, tctx, INF_TR_WHERE(tctx->queued_cpu, -1), 0);

	/*
	 * The task leaves while it still reports its live state, so a
	 * queued node is unlinked and a held path is released. Then the
	 * context is marked exiting.
	 */
	inf_task_leave(tctx);
	tctx->state = INF_ENTITY_EXITING;

	/*
	 * The task drops its reference on its cgroup entity. A cgroup that
	 * already exited is reclaimed when its last reference drops.
	 */
	inf_task_detach(tctx);

	/*
	 * Unlink any remaining node and wait for the last pop or steal
	 * hold. A non-zero return means a hold never dropped. The hold is a
	 * write into this node, so freeing the context below it would let a
	 * stale holder corrupt a recycled allocation. Count it, keep the
	 * context and stop: the live-context counter shows the leak instead
	 * of hiding it.
	 */
	ret = inf_queue_node_detach(&tctx->qnode);
	if (ret) {
		if (pool)
			__sync_fetch_and_add(&pool->detach_fail, 1);
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

	if (pool) {
		__sync_fetch_and_add(&pool->frees, 1);
		__sync_fetch_and_add(&pool->live, -1);
	}

	scx_task_free_rcu(p);
	return 0;
}

void BPF_STRUCT_OPS(infinity_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	task_ctx	   *tctx;
	inf_cpu_block_t	   *blk;
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

	/*
	 * The move settles the current reservation against the old
	 * ancestry before any queue change. The source value is not carried
	 * across the parent coordinate.
	 */
	inf_settle_slot(p, tctx, inf_slot_event(tctx),
			inf_resv_local(inf_cpu_ctx(tctx->path_cpu)));
	INF_STAT_INC(resv_move);

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
	cgrp	    = to ? to : inf_task_cgroup(p);
	leaf_parent = inf_resolve_leaf(blk, cgrp, &cgrp_id);
	leaf	    = inf_entity(blk, leaf_parent);
	if (!leaf)
		return;

	/* The task now references the destination entity. */
	inf_task_attach(tctx, blk, cpu, leaf_parent);
	tctx->cgrp_id = cgrp_id;

	/*
	 * The task starts at the frontier of the destination parent. The
	 * source value and the source residue are dropped.
	 */
	tctx->v_q16	 = leaf->frontier_q16;
	tctx->rem	 = 0;
	tctx->queued_cpu = cpu;
	tctx->path_cpu	 = cpu;

	/*
	 * A parked task keeps its parked state and history. It rejoins
	 * through the bandwidth release path, not from this callback.
	 */
	if (tctx->state == INF_ENTITY_PARKED)
		return;

	tctx->state = INF_ENTITY_INACTIVE;
	inf_admit_task(blk, tctx, leaf_parent, INF_INS_NORMAL);
	INF_STAT_INC(cgrp_cpu_moves);
	INF_STAT_INC(move_admits);
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
	u64		      id;

	if (!cgrp)
		return -EINVAL;

	id = inf_cgroup_id(cgrp);
	if (!id)
		return 0;

	st.cgrp_id = id;
	st.weight  = weight;
	st.idle	   = idle ? 1 : 0;
	st.present = 1;
	st.epoch   = scx_cgroup_ctl_epoch();
	/*
	 * A cgroup id can be reused. The generation names this control
	 * entry, so an entity of an earlier cgroup at the same id is known
	 * to be stale.
	 */
	st.gen = __sync_fetch_and_add(&inf_gen_counter, 1) + 1;

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

	return inf_cgroup_state_put(cgrp,
				    args ? args->weight : INF_WEIGHT_DEFAULT,
				    args ? args->sched_idle : false);
}

void BPF_STRUCT_OPS(infinity_cgroup_exit, struct cgroup *cgrp)
{
	inf_cpu_block_t *blk;
	u64		 id;
	u32		 idx;

	TOUCH_ARENA();

	scx_cgroup_ctl_cgroup_exit(cgrp);

	if (!cgrp)
		return;

	id = inf_cgroup_id(cgrp);
	if (!id)
		return;

	bpf_map_delete_elem(&cgrp_state_stor, &id);

	/*
	 * The exit is the only place that starts a reclaim. The entity of
	 * this CPU is reclaimed now when it has no reference; the entities
	 * of other CPUs are reclaimed at their next lookup. A busy entity
	 * stays dead and is reclaimed when its last reference drops.
	 */
	blk = inf_block(bpf_get_smp_processor_id());
	idx = blk ? inf_index_find(blk, id) : INF_IDX_NONE;
	if (idx != INF_IDX_NONE)
		inf_entity_release(blk, idx);
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
	int i, ret;
	u64 t0, t1;

	TOUCH_ARENA();

	if (ncpu > INF_MAX_CPUS)
		ncpu = INF_MAX_CPUS;
	if (!ncpu) {
		scx_bpf_error("infinity: no possible CPUs");
		return -EINVAL;
	}

	/*
	 * The service slot is measured from the scheduler clock. A clock
	 * that does not advance cannot measure a tick, so the load is
	 * blocked here instead of scheduling with a fabricated slot. The
	 * per-CPU tick probe seeds the real slot once tasks run.
	 */
	t0 = scx_bpf_now();
	t1 = t0;
	bpf_for(i, 0, INF_TICK_PROBE_INIT)
	{
		t1 = scx_bpf_now();
		if (t1 != t0)
			break;
	}
	if (t1 == t0) {
		scx_bpf_error(
			"infinity: the scheduler clock does not advance, so the service tick cannot be measured");
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

	/* Arm the diagnostic ring before the first transition. */
	inf_trace_arm();

	/*
	 * The entity store of every possible CPU: the group entities, the
	 * cgroup index and the occupancy bitmap. The block lives in the BPF
	 * arena and is never resized; a CPU index selects an entry.
	 */
	pages = (ncpu * (u32)sizeof(*inf_blocks) + PAGE_SIZE - 1) / PAGE_SIZE;
	inf_blocks =
		bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!inf_blocks) {
		scx_bpf_error("infinity: failed to allocate %u entity pages",
			      pages);
		return -ENOMEM;
	}
	inf_nr_blocks = ncpu;

	/* The root entity of every CPU is slot 0 and always exists. */
	bpf_for(cpu, 0, INF_MAX_CPUS)
	{
		inf_cpu_block_t	   *blk;
		inf_group_entity_t *root;

		if ((u32)cpu >= ncpu)
			break;

		blk = inf_block(cpu);
		if (!blk)
			continue;

		root = inf_entity(blk, 0);
		__builtin_memset(root, 0, sizeof(*root));
		root->cgrp_id	 = 0;
		root->weight	 = INF_WEIGHT_DEFAULT;
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
			cctx->slot_ns		= INF_SLOT_NS;
			cctx->tick_last		= 0;
			cctx->tick_deltas	= 0;
			cctx->tick_min_ns	= 0;
			cctx->tick_max_ns	= 0;
			cctx->tick_bad		= 0;
			cctx->tick_probe	= 0;
			cctx->steal_llc_cursor	= 0;
			cctx->steal_node_cursor = 0;
			cctx->resv.task_idx	= 0;
			cctx->resv.start_now	= 0;
			cctx->resv.policy_ns	= 0;
			cctx->resv.slot_ns	= INF_SLOT_NS;
			cctx->resv.cpu		= 0;
			cctx->resv.depth	= 0;
			cctx->resv.flags	= 0;
		}
	}

	return 0;
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
	       .init = (void *)infinity_init, .exit = (void *)infinity_exit,
	       /*
		* ENQ_LAST: the core hands the outgoing runnable task back to
		* ops.enqueue() after a dispatch that handed out nothing.
		* ENQ_EXITING and ENQ_MIGRATION_DISABLED: without them the core
		* bypasses ops.enqueue() for an exiting or migration-disabled
		* task and places it on a local DSQ itself
		* (scx_do_enqueue_task() in kernel/sched/ext/ext.c). A migration
		* disabled task on a remote rq then falls back to the global DSQ,
		* which no selection of this scheduler reads, so the task waits
		* for the watchdog with no scheduler reference at all. Both kinds
		* of enqueue reach this scheduler and take a tree admission.
		*/
	       .flags	   = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING |
			     SCX_OPS_ENQ_MIGRATION_DISABLED,
	       .timeout_ms = 20000, .name = "infinity");
