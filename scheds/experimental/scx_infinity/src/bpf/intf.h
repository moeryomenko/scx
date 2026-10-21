/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared definitions for scx_infinity.
 *
 * Revision 4 replaces the flat per-CPU ready queue with a hierarchical
 * entity tree. Each CPU owns one tree. The tree has a root entity, one
 * group entity per (cgroup, CPU) pair and one task entity per task. Every
 * level of the tree is an eligible deadline queue from lib/edq.h, ordered
 * by the normalized service value of its children.
 *
 * The service value is a Q16 nanosecond count that every level advances by
 * its own weight. A parent queue keeps a monotone frontier, and a 7:1 gate
 * decides whether an insertion takes the head or the tail of that queue.
 *
 * Placement is locality-first. The loader seeds one topology row per CPU
 * and one NUMA distance row per node, and the scheduler keeps the policy in
 * its own map. No shared helper carries it.
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

#define INF_PREEMPT_MARGIN_DEFAULT_NS 100000ULL
#define INF_PREEMPT_MARGIN_MAX_NS 1000000ULL
#define INF_STATS_INTERVAL_DEFAULT_MS 1000ULL

/* Copy of SCHED_NORMAL, SCHED_IDLE and SCHED_EXT from uapi/linux/sched.h. */
#define INF_SCHED_NORMAL 0
#define INF_SCHED_IDLE 5
#define INF_SCHED_EXT 7

/*
 * One service slot is one ops.tick() call. The slot is the band width and
 * the dispatch slice. It is not a wall-clock promise.
 */
#define INF_SLOT_NS 1000000ULL

/*
 * The largest charge one settlement can add. A slot that runs longer is
 * clamped to it and the clamp is counted.
 */
#define INF_SETTLE_MAX_NS 4000000ULL

/*
 * The service slot is measured, not assumed. A local tick records the
 * scx_bpf_now() delta of the reservation. The first INF_TICK_PROBE_SLOTS
 * deltas seed the per-CPU slot, and the slot stays inside the bounds
 * below. A tick that delivers no delta is counted; enough of them block
 * the run instead of charging a fabricated slot.
 */
#define INF_TICK_PROBE_SLOTS 16
#define INF_TICK_UNMEASURABLE_MAX 32
#define INF_SLOT_MIN_NS 100000ULL
#define INF_SLOT_MAX_NS INF_SETTLE_MAX_NS
/* Bounded probe of the scheduler clock at load time. */
#define INF_TICK_PROBE_INIT 4096

/* Q16 fixed point service units. */
#define INF_Q16_SHIFT 16

/* One nanosecond at weight 1, in Q16 service units: 100 * 2^16. */
#define INF_SERVICE_SCALE (100ULL << INF_Q16_SHIFT)

/* The band width in Q16 service units: one slot. */
#define INF_BAND_Q16 (INF_SLOT_NS << INF_Q16_SHIFT)

/* The largest charge one settlement can add, in Q16 service units. */
#define INF_SETTLE_MAX_Q16 (INF_SETTLE_MAX_NS * INF_SERVICE_SCALE)

/* A band scan inspects at most this many entities. */
#define INF_BAND_SCAN_MAX 16

/*
 * The number of cgroup levels the entity chain keeps. A task in a deeper
 * cgroup joins the deepest ancestor that has an entity.
 */
#define INF_CHAIN_MAX 4

/* The counters of the per-CPU scans. */
#define INF_MAX_COUNTERS 8
#define INF_COUNTER_BAND 0
#define INF_COUNTER_PEEK 1
/* The number of parent queues the current selection has inspected. */
#define INF_COUNTER_DEPTH 2
/* The attempt of the current selection, counted in the arena. */
#define INF_COUNTER_RETRY 3

/* One tail insertion in every eight normal insertions. */
#define INF_GATE_MASK 7U

/*
 * The handoff points of the scheduler. A handoff starts when the
 * scheduler releases its own reference to a task and ends when the task
 * is running, queued in a tree, in a local DSQ, parked, or owned by the
 * core. The five kinds are also the fault-injection names of
 * --test-handoff-fail KIND:COUNT, so their order is part of the loader
 * and harness contract.
 */
#define INF_HO_NONE 0
#define INF_HO_DSQ 1 /* a local DSQ submission */
#define INF_HO_DEST_INSERT 2 /* the destination leaf insert of a steal */
#define INF_HO_SOURCE_REMOVE 3 /* the source queue removal of a steal */
#define INF_HO_STEAL 4 /* the steal move as one handoff */
#define INF_HO_HOLD 5 /* the queue hold of a move */
#define INF_HO_KINDS 6

/*
 * The in-flight handoffs one CPU keeps. A dispatch hands out one task per
 * call, so a handful covers the tasks that have left the tree and have
 * not started yet. An entry that is still open after one service slot is
 * a task in core custody: dispatch rescues it.
 */
#define INF_HO_SLOTS 4

/*
 * The maximum number of group levels of one entity chain, from the leaf
 * parent to the child of the root. A task whose cgroup is deeper joins the
 * deepest ancestor that has an entity, so this is also the bound of the
 * chain that a selection walks.
 */
#define INF_MAX_LEVELS 4

/*
 * The number of parent queues one selection inspects. A chain of
 * INF_MAX_LEVELS group levels puts a task in the queue below the deepest
 * group, so the descent needs four group steps plus the terminal queue that
 * holds the task. The bound was INF_MAX_LEVELS, which refused the terminal
 * queue of a four-level chain: the fourth winner was a group, the loop ran
 * out, and the selection returned no leaf while the group still held
 * runnable tasks. That is the stall this bound fixes.
 */
#define INF_SEL_DEPTH_MAX (INF_MAX_LEVELS + 1)

/* The number of times a selection restarts after it repairs a stale level. */
#define INF_SELECT_RETRY_MAX 4

/* Group entities per CPU and the open-addressed index slots per CPU. */
#define INF_GROUPS_PER_CPU 128
#define INF_INDEX_SLOTS 256

/* Task entities in the pool. A full pool fails ops.init_task(). */
#define INF_TASKS_MAX 65536

/* Entity weights. A task uses its nice weight, a group its cpu.weight. */
#define INF_WEIGHT_MIN 1U
#define INF_WEIGHT_MAX 10000U
#define INF_WEIGHT_IDLE 3U
#define INF_WEIGHT_DEFAULT 100U

#define INF_MAX_CPUS 1024
#define INF_MAX_CGROUPS 2048
#define INF_MAX_NODES 64

/* At most eight peers are examined in each dispatch steal tier. */
#define INF_STEAL_SCAN_MAX 8

/*
 * The live control state of one cgroup, keyed by the cgroup id. The
 * scheduler reads it when it latches a group weight and when it refreshes
 * one at an epoch boundary. A cgroup without an entry has the default
 * weight.
 *
 * gen is a scheduler-private generation. A cgroup id can be reused after
 * an exit, so an entity compares gen against the live entry before it
 * trusts its history.
 */
struct inf_cgrp_state {
	u64 cgrp_id;
	u64 epoch;
	u64 gen;
	u32 weight;
	u32 idle;
	u32 present;
	u32 pad;
};

/*
 * The entity states, mirrored by the Rust model. A group entity is
 * RUNNABLE while it sits in its parent queue, SELECTED while a running
 * path holds it, and INACTIVE while it has no dispatchable descendant.
 */
#define INF_ENTITY_INACTIVE 0
#define INF_ENTITY_RUNNABLE 1
#define INF_ENTITY_SELECTED 2
#define INF_ENTITY_RUNNING 3
#define INF_ENTITY_PARKED 4
#define INF_ENTITY_HANDOFF 5
#define INF_ENTITY_EXITING 6

/* The insertion class of an entity inside its parent queue. */
#define INF_CLASS_HEAD 0
#define INF_CLASS_TAIL 1

/*
 * The insertion modes of the frozen event table. A normal insertion takes
 * one gate step in the parent queue and the gate decides head or tail. A
 * tail insertion takes the tail without a gate step. A head-exempt
 * insertion takes the head without a gate step.
 */
#define INF_INS_NORMAL 0
#define INF_INS_TAIL 1
#define INF_INS_HEAD 2

/*
 * The events of the frozen event table. The class and the gate of each row
 * are fixed.
 */
#define INF_EV_NONE 0
#define INF_EV_ADMIT 1
#define INF_EV_ADMIT_HEAD 2
#define INF_EV_POST_SLOT 3
#define INF_EV_EXPIRY 4
#define INF_EV_YIELD 5
#define INF_EV_PREEMPT 6
#define INF_EV_QUOTA 7
#define INF_EV_REWEIGHT 8
#define INF_EV_MOVE 9
#define INF_EV_STEAL 10
#define INF_EV_STEAL_FAIL 11
#define INF_EV_YIELD_TO 12

/* Peer steal tiers and the per-tier scan bound. */
#define INF_STEAL_MAX_PEERS 2
/*
 * Upper bound on the CPU ids one tier walk inspects. The walk stops after
 * eight peers in the tier; this bound keeps the verifier state small on a
 * machine with many CPUs. The cursor carries the walk forward, so a peer
 * outside the window is reached on a later dispatch.
 */
#define INF_STEAL_SCAN_CPUS 64
#define INF_STEAL_LLC 0
#define INF_STEAL_NODE 1

/*
 * Arena allocation size for the task context. The real struct embeds the
 * cgroup bandwidth context at offset 0 and one queue node. The loader only
 * needs the size, which a static assertion in main.bpf.c checks.
 */
#define INF_TASK_CTX_SIZE 688

/*
 * One queue node per task. The node is struct scx_edq_task.
 */
#define INF_QUEUE_NODE_BYTES 96

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
 * share at most 10000, so a weight stays well below 2^32.
 */
#define INF_WEIGHT_CAP (1ULL << 32)

/*
 * Live configuration. The loader owns the single array entry and replaces
 * it with one map update, so the BPF side never observes a partial
 * configuration. Queue order and expiry stay compile-time constants.
 *
 * quantum_ns is not read by revision 4: one service slot is one measured
 * kernel tick. The field stays until the change that removes it from the
 * userspace layout lands.
 */
struct inf_cfg {
	u64 quantum_ns;
	u64 preempt_margin_ns;
	u32 placement_mode;
	u32 smt_enabled;
	u32 spill_threshold;
	u32 generation;
};

/*
 * The reservation of one running slot. One CPU runs one task at a time,
 * so the reservation lives in the per-CPU context. It opens in
 * ops.running() and a settle closes it, so the actual runtime of a slot
 * is charged exactly once. It cannot open at the dispatch: the core calls
 * ops.stopping() for the outgoing task after ops.dispatch(), so a
 * dispatch-time reservation would take the CPU slot before the
 * predecessor settled its own runtime.
 *
 * task_idx is the pid of the reserved task. start_now is the
 * actual-runtime cursor, set by ops.running(). policy_ns is the policy
 * service already charged to the path. latched[] is the weight of each
 * group level at the start of the slot, and ancestry[] is the entity
 * index of that level, leaf parent first. slot_ns is the reserved slot.
 */
struct inf_reservation {
	u64 task_idx;
	u64 start_now;
	u64 policy_ns;
	u64 slot_ns;
	u64 latched[INF_MAX_LEVELS];
	u32 ancestry[INF_MAX_LEVELS];
	u32 cpu;
	u32 depth;
	u32 flags;
};

/* The reservation flags. */
#define INF_RESV_RUNNING 1U /* start_now holds a valid cursor */
#define INF_RESV_YIELD 2U /* explicit yield: the policy floor is slot_ns */

/*
 * The path of a selection: the group entities from the leaf parent to the
 * root, and the service minimum of every queue the selection inspected. It
 * is the scratch of one selection and the record of one held path.
 *
 * ent[] holds one group per descent, so it is INF_MAX_LEVELS long. vmin[]
 * holds the minimum of every inspected queue, the terminal queue included,
 * so it is INF_SEL_DEPTH_MAX long. The selected task is the terminal
 * inspection: it is found in the queue at depth path->depth, whose owner is
 * ent[path->depth - 1], or the root entity when path->depth is zero.
 */
struct inf_path {
	u32 ent[INF_MAX_LEVELS];
	u64 vmin[INF_SEL_DEPTH_MAX];
	u32 depth;
	u32 pad;
};

/*
 * The reason a local selection returned no leaf. Each one is a distinct
 * defect or a normal empty tree, so a stall report names the one that
 * happened instead of saying that nothing was found.
 */
#define INF_SEL_EMPTY 1 /* a visited queue had no child */
#define INF_SEL_SCAN 2 /* the band scan could not take a queue lock */
#define INF_SEL_ZERO_COUNT 3 /* the winning group had no dispatchable child */
#define INF_SEL_RETRY 4 /* the restart bound ran out */
#define INF_SEL_DEPTH 5 /* a group entity below INF_MAX_LEVELS */
#define INF_SEL_NO_ENTITY 6 /* a visited parent index has no entity */
#define INF_SEL_REASONS 8 /* power of two, indexes 0..INF_SEL_REASONS-1 */

/* The flags of one inspected queue. */
#define INF_SEL_F_FIRST_GROUP 1U /* the queue head is a group entity */
#define INF_SEL_F_ROOT_GROUP 2U /* the tree root is a group entity */
#define INF_SEL_F_EMPTY 4U /* the queue had no child */
#define INF_SEL_F_WIN_GROUP 8U /* the winner is a group entity */

/*
 * One parent queue that a selection inspected.
 *
 * A raw arena address cannot be stored in a map value, so the queue root
 * and its head are named by identity: the entity index for a group entity
 * and the pid for a task. count, state, refs and generation are the fields
 * of the winning group entity that decide whether its children are
 * reachable and dispatchable. scan is the return value of the band scan of
 * that queue.
 */
struct inf_sel_level {
	u64 v; /* service value of the winner */
	u64 vmin; /* service minimum of the queue */
	u64 count; /* dispatchable children of the winner */
	u64 nr; /* children in the queue */
	u64 generation; /* cgroup generation of the winner */
	u64 frontier; /* frontier of the queue */
	u32 parent; /* entity index of the queue owner */
	u32 child; /* entity index of the winner, INF_IDX_NONE for a task */
	s32 first; /* identity of the queue head */
	s32 root; /* identity of the queue tree root */
	s32 pid; /* pid of the winner when it is a task */
	u32 depth; /* depth of the queue, root is zero */
	u32 state; /* state of the winner */
	u32 refs; /* hold count of the winner */
	u32 scan; /* inf_band_scan() return, as a signed value */
	u32 class; /* insertion class of the winner */
	u32 flags; /* INF_SEL_F_* */
};

/*
 * The persistent dispatch snapshot of one CPU.
 *
 * A selection that finds no leaf records every queue it inspected here
 * before the steal overwrites the selection scratch of that CPU. The record
 * is written at the failure, not at exit: the exit snapshots of
 * inf_dump_queues() run after the disable pass has emptied every tree, so
 * they cannot show a stalled state.
 *
 * The map is pinned in bpffs, so the entry outlives the scheduler process
 * and user space reads it after the run. It is never cleared by the
 * scheduler, and it is taken before stealing on purpose: a steal that
 * succeeds would otherwise erase the only record of a local selection that
 * handed out nothing while the tree still held tasks.
 *
 * reason_count[] counts every failure by reason, so a clean run shows that
 * the depth, retry, zero-count and scan reasons never happened, not only
 * that the last one did not.
 */
struct inf_dispatch_snap {
	u64 ts; /* scx_bpf_now() of the last failure */
	u64 reason_count[INF_SEL_REASONS]; /* failures per reason */
	u64 cpu;
	u64 depth; /* the advisory tree depth at the failure */
	u64 generation; /* live configuration generation */
	u64 attempts; /* selection attempts of the last failure */
	/*
	 * What the core holds for this CPU at the failure. nr_running is
	 * every task the core counts as queued on this runqueue, in this
	 * scheduler's tree, in its local DSQ or in no queue at all. The
	 * tree and the local DSQ are visible to this scheduler.
	 *
	 * A runnable @prev is the third place a counted task can be. The
	 * core enqueues it after ops.dispatch() returns, so it is outside
	 * both structures at the failure. The corrected formula is
	 *
	 *   missing = nr_running - depth - local_nr - prev_runnable
	 *
	 * and a nonzero value is a task in core custody that no scheduler
	 * structure holds. Without the subtraction the record counts the
	 * outgoing task as lost and proves nothing.
	 */
	u64 core_nr_running;
	u64 core_local_nr;
	u64 core_missing;
	u64 core_prev_runnable; /* @prev was runnable and not yet enqueued */
	u64 band_full; /* band scans that reached INF_BAND_SCAN_MAX */
	u64 band_tail_node; /* of those, the first uninspected child */
	u64 band_tail_null; /* of those, the queue ended at the bound */
	u32 reason; /* INF_SEL_* of the last failure */
	u32 cause; /* reason of the last restart, zero when none */
	u32 nr_levels; /* levels recorded */
	u32 pad;
	struct inf_sel_level lvl[INF_SEL_DEPTH_MAX];
};

/*
 * The callbacks of this scheduler, for the callback history of a CPU. A
 * record names the callback and not its arguments, so a reader can tell a
 * CPU that stops dispatching from a CPU that dispatches and finds nothing.
 */
#define INF_CB_NONE 0
#define INF_CB_SELECT_CPU 1
#define INF_CB_ENQUEUE 2
#define INF_CB_RUNNING 3
#define INF_CB_TICK 4
#define INF_CB_STOPPING 5
#define INF_CB_DEQUEUE 6
#define INF_CB_QUIESCENT 7
#define INF_CB_DISPATCH 8
#define INF_CB_YIELD 9
#define INF_CB_SET_WEIGHT 10
#define INF_CB_CGROUP_MOVE 11
#define INF_CB_EXIT_TASK 12
#define INF_CB_NAMES 13

/* The number of callback names kept per CPU. A power of two, so the ring
 * index is a mask and the verifier can bound the array access. */
#define INF_CB_HISTORY 4

/*
 * One tick-side or dispatch-side record of a CPU.
 *
 * The dispatch snapshot of inf_dispatch_snap records a failed selection.
 * This record is wider: it also carries what the core holds for the CPU,
 * so a stall is named as one of two states. Either the tree holds the task
 * and the selection cannot reach it, or the core counts a queued task that
 * the tree does not hold, which means the task is in core custody with no
 * scheduler reference. The second state is invisible to the selection and
 * is what the tick-side record is for.
 *
 * nr_running and local_nr are read from the core's own runqueue. A queued
 * task of this scheduler is on that runqueue's runnable list whether it
 * sits in the tree or in no queue at all, so nr_running above the tree
 * depth is the signature of the second state.
 */
struct inf_core_entry {
	u64 ts; /* scx_bpf_now() at the record */
	u64 depth; /* advisory tree depth of this CPU */
	u64 nr_running; /* the core's queued tasks on this runqueue */
	u64 local_nr; /* tasks in the core's local DSQ */
	u64 last_disp_ns; /* scx_bpf_now() of the last dispatch */
	u64 resv_pid; /* reservation owner, 0 when closed */
	s32 curr_pid; /* pid of the core's current task */
	u32 curr_idle; /* the current task is the idle task */
	u32 curr_slice; /* slice of the current task */
	u32 tag; /* INF_CB_* of the callback that wrote the record */
	u32 stranded; /* depth is zero while the core counts queued tasks */
	u32 cb[INF_CB_HISTORY]; /* last callbacks of this CPU, newest last */
	u32 pad;
};

/* One per-CPU ring of inf_core_entry, pinned for a post-run read. */
#define INF_CORE_SNAP_SLOTS 8

struct inf_core_snap {
	u64 next; /* records written, index of the next slot */
	struct inf_core_entry slot[INF_CORE_SNAP_SLOTS];
};

/*
 * The last enqueue and the last dispatch submission of one task.
 *
 * A task that strands in the core's custody is in no queue of this
 * scheduler, so no structure of the policy can name it. This record is
 * written at the enqueue that can strand it, and the watchdog names the
 * pid, so the two together attribute the loss. The entry is indexed by the
 * low bits of the pid and carries the whole pid, so a reader rejects an
 * entry that a colliding task overwrote. The fields separate the ways a
 * runnable task can be lost:
 *
 * - enq_flags and admit_ret: the enqueue. SCX_ENQ_LAST means the core
 *   re-enqueued the outgoing task after an empty dispatch and needs a
 *   follow-up scheduling event, and admit_ret is the tree admission
 *   result of that enqueue.
 * - dsq_ret: the last local DSQ submission for the task. A refused
 *   submission leaves the task in this scheduler's hand, not in the
 *   core's.
 * - kick: whether the enqueue issued the follow-up event. A LAST enqueue
 *   with a successful admission and a kick names the event, not the
 *   enqueue.
 *
 * enq_gen counts every enqueue of the task, so a reader can tell whether
 * the record describes the enqueue that stranded it. A pid with no record
 * was never enqueued with SCX_ENQ_LAST and never failed an enqueue or a
 * submission: it lost its ownership some other way.
 */
struct inf_enq_rec {
	u64 ts; /* scx_bpf_now() of the record */
	u64 enq_flags; /* enq_flags of the recorded enqueue */
	u64 enq_gen; /* enqueue generation of the task */
	s64 admit_ret; /* tree admission result, 0 when it entered */
	s64 dsq_ret; /* last local DSQ submission, 0 on success */
	s32 pid;
	u32 state; /* task state at the record */
	s32 queued_cpu; /* the CPU whose tree holds the task */
	s32 path_cpu; /* the CPU that owns the held path */
	u32 kick; /* the enqueue issued the follow-up kick */
	u32 path_depth; /* group levels of the held path */
};

/* Task records kept in the pinned map. A power of two, so the pid index
 * is a mask. A campaign has a few thousand tasks and only the enqueues
 * that can strand one take a record. */
#define INF_ENQ_SNAP_MAX 2048

/* The pids one CPU remembers for the custody check. A power of two. */
#define INF_TT_TRACK_SLOTS 16

/*
 * The custody checks a CPU must count a gap in a row before the check names
 * a stranded task. One sample can land inside a handoff window; eight
 * consecutive samples of the same CPU span at least one service slot and
 * cannot be a window.
 */
#define INF_TT_MISS_RUN 8

struct inf_cpu_ctx {
	struct inf_reservation resv;
	u64		       root_idx;
	/* The measured service slot of this CPU. */
	u64 slot_ns;
	u64 tick_last; /* scx_bpf_now() of the previous local tick */
	u64 tick_deltas; /* measured local tick deltas */
	u64 tick_sum_ns;
	u64 tick_min_ns;
	u64 tick_max_ns;
	u64 tick_bad; /* local ticks without a measurable delta */
	/* The number of dispatchable entities in the tree, advisory. */
	s64 depth;
	u32 seq;
	u32 tick_probe; /* local ticks counted for the slot seed */
	u32 steal_llc_cursor;
	u32 steal_node_cursor;
	u32 online;
	/* Callback storm diagnosis: how often each callback ran per CPU. */
	u64 disp_calls; /* ops.dispatch invocations */
	u64 disp_empty; /* dispatches that handed out nothing */
	u64 stop_calls; /* ops.stopping invocations */
	u64 run_calls; /* ops.running invocations */
	u64 enq_calls; /* ops.enqueue invocations */
	u64 q_calls; /* ops.quiescent invocations */
	u64 deq_calls; /* ops.dequeue invocations */
	u64 tick_calls; /* ops.tick invocations */
	u64 last_disp_ns; /* scx_bpf_now() of the last dispatch */
	/* The last callbacks of this CPU, newest at index cb_next - 1. */
	u32 cb[INF_CB_HISTORY];
	u32 cb_next;
	u32 pad[2];
	/*
	 * The in-flight handoffs of this CPU: every task this CPU handed to
	 * a local DSQ that has not started yet. The ring is written at the
	 * submission and cleared at ops.running(). An entry that survives
	 * more than one service slot is a task the core holds with no
	 * scheduler reference, and the dispatch rescues it and counts
	 * core_rescues.
	 */
	u64 ho_pid[INF_HO_SLOTS];
	u64 ho_start_ns[INF_HO_SLOTS];
	u32 ho_seq;
	u32 pad_ho;
	/*
	 * The tasks this CPU admitted, newest first. A stranded task is in no
	 * queue of this scheduler, so the tree, the queues and the selection
	 * cannot name it. This ring keeps the pids the CPU handled recently,
	 * and the custody check of ops.tick() and ops.dispatch() tests each
	 * one against the core's own state. The ring is written only when the
	 * diagnostic trace is enabled.
	 */
	u64 tt_pid[INF_TT_TRACK_SLOTS];
	u32 tt_next;
	/* Set by the first dispatch of this CPU that sees a custody gap. */
	u32 custody_seen;
	/*
	 * Consecutive custody checks that counted more runnable tasks than
	 * the tree, the local DSQ and the outgoing task hold. One sample is
	 * a window; a sustained count is a task in core custody with no
	 * scheduler reference.
	 */
	u32 miss_run;
	u32 pad_mr;
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
	u32 head_kflags;
	s64 head_ops_state;
	s32 head_runnable_cpu;
	u32 pad;
};

/* NUMA distance row for one node. The key of the map entry is the node. */
struct inf_node_topo {
	u32 distance[INF_MAX_NODES];
};

/* One slot of the per-task transition history kept in the task context. */
struct inf_hist {
	u32 op;
	s32 src;
	s32 dst;
	s32 result;
	u32 state;
	u32 pad;
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
	u8  qnode[INF_QUEUE_NODE_BYTES];
	u64 v_q16;
	u64 rem;
	u64 tie;
	u64 latched_weight;
	u64 epoch;
	u64 parent_idx;
	u64 cgrp_id;
	u64 slice_ns;
	u64 last_running_ns;
	u64 park_ns;
	u64 base_weight;
	u64 pending_weight;
	u32 path_ent[INF_MAX_LEVELS];
	s32 queued_cpu;
	s32 path_cpu;
	s32 cgrp_cpu;
	u32 path_depth;
	u32 state;
	u32 class;
	u32		moving;
	u32		dequeue_pending;
	u32		exit_pending;
	u32		reweight_pending;
	u32		joined;
	u32		yielded;
	u32		preempted;
	u32		wake_fork;
	u32		idle;
	u32		pid;
	u32		pending_event;
	u32		hist_idx;
	struct inf_hist hist[8];
	/*
	 * The enqueue and submission record of this task. enq_gen counts
	 * every enqueue, so a published record of inf_enq_rec can be told
	 * apart from a later enqueue. last_dsq_ret is the result of the last
	 * local DSQ submission for the task: a nonzero value means the core
	 * refused it, so the task never entered a core queue.
	 */
	u64 enq_gen;
	u64 last_enq_flags;
	s64 last_dsq_ret;
	/* One when the task has an in-flight handoff that has not closed. */
	u32 ho_pending;
	u32 pad_ho;
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
	/*
	 * One counter per bandwidth integration point. The quota path is a
	 * chain of hooks, and a chain that never fires is invisible without
	 * them: bw_gate counts the enqueue hooks that reach the throttle
	 * test, bw_eagain the ones it refuses, bw_park_ok the tasks the
	 * backlog accepted, bw_cb the reenqueue callbacks the library runs,
	 * bw_drain the dispatch drains, bw_consume the settles that pass
	 * actual runtime, and bw_consume_ns the runtime they pass, so the
	 * sum can be compared with the cgroup's own cpu.stat.
	 */
	u64 bw_gate;
	u64 bw_eagain;
	u64 bw_terr;
	u64 bw_park_ok;
	u64 bw_park_fail;
	u64 bw_cb;
	u64 bw_drain;
	u64 bw_drain_err;
	u64 bw_consume;
	u64 bw_consume_ns;
	u64 bw_consume_err;
	u64 bw_consume_skip;
	u64 bw_set;
	u64 bw_set_err;
	u64 bw_init;
	u64 bw_init_err;
	u64 bw_move;
	u64 bw_move_err;
	u64 bw_cancel;
	u64 bw_lib_init_err;
	/* Renewed slots that opened a reservation for the slot they renew. */
	u64 resv_renew;
	/*
	 * The actual-runtime charge, split by the locality of the slot it
	 * settles. A local settle reads the clock of the CPU that runs the
	 * task; a remote settle cannot and counts one reserved slot. The
	 * two sums tell which one the runtime of a run came from.
	 */
	u64 settle_local;
	u64 settle_local_ns;
	u64 settle_remote;
	u64 settle_remote_ns;
	u64 settle_max_ns;
	u64 settle_over_slot;
	/*
	 * The residency of a parked task: the sum of the intervals between
	 * the put-aside and the reenqueue callback, and the number of parks
	 * that closed. A parked task is re-enqueued when its period refills,
	 * so the residency of a 50 percent quota is about half its period.
	 */
	u64 bw_park_wait_ns;
	u64 bw_park_closed;
	u64 bw_park_open_max_ns;
	u64 cgrp_eff_weight;
	u64 cgrp_eff_min;
	u64 cgrp_eff_max;
	u64 cgrp_eff_samples;
	u64 cgrp_scale;
	u64 cgrp_refolds;
	u64 deq_core_sched_exec;
	u64 deq_sleep;
	u64 deq_sched_change;
	u64 deq_keep;
	u64 q_sleep;
	u64 q_sched_change;
	u64 q_keep;
	u64 cgrp_cpu_moves;
	u64 steals;
	u64 steal_llc;
	u64 steal_node;
	u64 yield_to_moves;
	u64 reweight_moves;
	u64 stale_pops;
	u64 lost_state_errors;
	u64 requeues;
	u64 weight_changes;
	u64 reweight_queued;
	u64 weight_queued_cpu;
	u64 exit_passes;
	u64 enq_no_ctx;
	u64 enq_no_cctx;
	/*
	 * The follow-up event of an SCX_ENQ_LAST admission. The core
	 * re-enqueues the outgoing runnable task with that flag after an
	 * empty dispatch and keeps the CPU only if the scheduler asks for
	 * another dispatch, so an admission without the kick ends the
	 * dispatch loop and the task waits for the watchdog. enq_last counts
	 * the flag, enq_last_kicks counts the deferred kicks issued for it,
	 * and enq_records counts the records published to enq_stor.
	 */
	u64 enq_last;
	u64 enq_last_kicks;
	u64 enq_records;
	/* The SCX_ENQ_LAST enqueues that left by the exit and park paths. */
	u64 enq_last_exit;
	u64 enq_last_park;
	u64 stale_requeues;
	u64 stale_skips;
	/* Dispatch outcome and normalizer, for the share diagnosis. */
	u64 disp_pop;
	u64 disp_renew;
	u64 disp_total;
	u64 disp_q;
	/* Revision-4 counters. */
	u64 entity_overflow;
	u64 entity_own; /* the resolved leaf is the task's own cgroup */
	u64 entity_ancestor; /* the resolved leaf is an ancestor entity */
	u64 entity_reclaims;
	u64 entity_alloc_fail;
	u64 band_scan_truncated;
	u64 half_range_faults;
	u64 settle_clamps;
	u64 remote_slots;
	u64 state_repairs;
	u64 steal_failures;
	u64 steal_refusals;
	u64 ctl_map_overflow;
	u64 path_depth_max;
	u64 disp_tree;
	u64 disp_steal;
	u64 tick_slots;
	u64 requeue_tail;
	u64 requeue_normal;
	u64 disp_remove_fail;
	u64 disp_remove_einval;
	u64 disp_stale_state;
	u64 disp_stale_inactive;
	u64 disp_stale_selected;
	u64 disp_stale_running;
	u64 disp_dsq_fail;
	u64 disp_affinity_fail;
	u64 enq_admit_fail;
	u64 pid_sample;
	/*
	 * Reservation, tick, epoch, parking and reclamation counters. Every
	 * refused, clamped, repaired and failed path has one of these.
	 */
	u64 resv_open;
	u64 resv_settled;
	u64 resv_closed; /* a settle found the reservation closed */
	u64 resv_mismatch; /* the reservation belongs to another task */
	u64 resv_stop;
	u64 resv_migrate;
	u64 resv_move;
	u64 resv_exit;
	u64 resv_remote;
	u64 resv_yield; /* explicit yield raised the policy total */
	u64 resv_yield_extra_ns; /* the difference debited to V */
	u64 resv_actual_ns; /* total actual runtime of closed slots */
	u64 resv_policy_ns; /* total policy service of closed slots */
	u64 tick_measured; /* local ticks with a usable delta */
	u64 tick_unmeasurable; /* local ticks with no usable delta */
	u64 tick_probe_done; /* CPUs whose slot seed completed */
	u64 slot_ns_measured; /* the last seeded slot */
	u64 slot_ns_min;
	u64 slot_ns_max;
	u64 epoch_deferred; /* running task defers a new weight */
	u64 epoch_applied; /* the deferred weight took effect */
	u64 park_settled; /* the reservation closed before parking */
	u64 park_failed; /* put-aside refused, the task stayed queued */
	u64 unpark_admits; /* a parked task rejoined the tree */
	u64 entity_ref_busy; /* a reclaim found live references */
	u64 entity_stale_gen; /* a cgroup id was reused */
	u64 entity_reuse_busy; /* a stale entity still owns the index */
	u64 move_admits; /* a cgroup move inserted a task */
	u64 migrate_admits; /* a CPU migration inserted a task */
	u64 reclaims_deferred; /* the reclaim waits for the last reference */
	u64 admit_no_parent; /* an admission found no leaf entity */
	u64 requeue_no_block; /* a requeue found no entity block */
	u64 requeue_no_leaf; /* a requeue found no leaf entity */
	u64 rekey_fail; /* an ancestor re-key could not re-enter its queue */
	/*
	 * Tree-path consistency counters. A runnable task reaches the
	 * selection only while its leaf entity sits in the child queue of its
	 * parent and every ancestor does the same. Each way that invariant can
	 * break has its own counter, so a stalled run names the broken link.
	 */
	u64 link_lost; /* a counted entity is not in its parent queue */
	u64 count_lost; /* an entity left its parent queue with children */
	u64 count_repairs; /* an entity count repaired from its queue */
	u64 admit_unlinked; /* a task entered a leaf that is not linked */
	u64 disp_empty_lost; /* the tree had depth but nothing to select */
	/*
	 * Ownership counters of the core callbacks. An unowned event means the
	 * core ran, stopped or dequeued a task that this context does not hold
	 * in the state the event implies.
	 */
	u64 run_unowned; /* ops.running for a task not selected or running */
	u64 stop_unowned; /* ops.stopping for a task not selected or running */
	/*
	 * The state each callback observed, indexed by the entity state and
	 * by whether the task still names a queue CPU:
	 *
	 *   index = (state & 7) | (queued_cpu >= 0 ? 8 : 0)
	 *
	 * A clean run is run_state[2] == stop_state[3] == the number of
	 * starts, and every other slot is zero. The two slots a start can
	 * legitimately occupy without a tree admission are named in the
	 * evidence: a restored current task, whose dequeue the core undoes
	 * with ENQUEUE_RESTORE, and an exit hand-back.
	 */
	u64 run_state[16];
	u64 stop_state[16];
	/*
	 * The starts and stops of a task that the enqueue handed to the local
	 * DSQ because it is exiting. They are counted in run_unowned and
	 * stop_unowned, and this pair separates them from a start that lost
	 * its admission: a clean run keeps run_unowned equal to
	 * run_exit_handoff and stop_unowned equal to stop_exit_handoff.
	 */
	u64 run_exit_handoff;
	u64 stop_exit_handoff;
	u64 q_unowned; /* ops.quiescent ended a period this context lost */
	u64 slot_end_stop; /* a live slot ended in ops.stopping */
	u64 disp_renew_unowned; /* a renew refused an unowned previous task */
	u64 runnable_unlinked; /* a runnable task was in no reachable queue */
	u64 resv_none; /* a settle found no slot of its task */
	u64 resv_stale; /* a start closed a slot whose owner had gone */
	u64 depth_under; /* a depth decrement found nothing counted */
	u64 depth_mismatch; /* depth disagreed with the root count */
	u64 admit_fallbacks; /* a refused leaf admission re-entered at the root */
	u64 stop_slice_refused; /* the core refused the end-of-slot write */
	/*
	 * Preemption decision counters, one per refusal path. A refusal
	 * changes no state, so only the counter moves.
	 */
	u64 preempt_checks; /* wakeups that reached the decision */
	u64 preempt_refuse_flags; /* not a wakeup, no decision taken */
	u64 preempt_refuse_policy; /* not SCHED_NORMAL or SCHED_EXT */
	u64 preempt_refuse_fork; /* the wakeup followed a fork */
	u64 preempt_refuse_idle; /* idle cgroup or SCHED_IDLE task */
	u64 preempt_refuse_not_winner; /* the wakee does not win its path */
	u64 preempt_refuse_no_victim; /* no distinct queued victim */
	u64 preempt_refuse_slice; /* the victim has too little slice left */
	/* Steal transaction counters, one per refusal and rollback path. */
	u64 steal_peek_empty; /* the peer tree had no band winner */
	u64 steal_affinity_refusals; /* the task is not allowed on the CPU */
	u64 steal_owner_refusals; /* another writer owned the handoff */
	u64 steal_revalidate_refusals; /* the destination refused the move */
	u64 steal_insert_refusals; /* the destination leaf insert failed */
	u64 steal_fault_missing; /* the fault map lookup failed */
	u64 steal_fault_taken; /* a forced destination refusal was consumed */
	u64 steal_attempts; /* steals that reached the handoff */
	u64 steal_rollbacks; /* the source record was restored */
	u64 steal_remote_refusals; /* local work blocked the node tier */
	/* Yield-to decision counters, one per refusal path. */
	u64 yield_to_checks; /* yield calls that carried a target */
	u64 yield_to_refuse_state; /* the target is not queued and runnable */
	u64 yield_to_refuse_running; /* the target is running or dispatched */
	u64 yield_to_refuse_band; /* the target is outside its band */
	u64 yield_to_insert_fail; /* the promotion insert failed */
	/*
	 * Handoff instrumentation. The revision-4 stall gate reads these
	 * keys from the statistics line:
	 *
	 *   ticks               one ops.tick call, one service slot
	 *                       (the field is tick_slots)
	 *   handoffs            completed handoff operations
	 *   handoff_max_ns      the longest completed handoff
	 *   handoff_overdue     a completed handoff longer than one slot
	 *   handoff_orphans     a handoff still open past one slot
	 *   handoff_duplicates  a task handed out twice without starting
	 *   faults_injected     injected handoff failures consumed
	 *
	 * A handoff operation is short and runs with the runqueue locked, so
	 * a completed one is far below one slot. An orphan is the opposite
	 * case: the scheduler released the task and the core never placed
	 * it, which is the state that used to end at the watchdog.
	 */
	u64 handoffs;
	u64 handoff_max_ns;
	u64 handoff_overdue;
	u64 handoff_orphans;
	u64 handoff_duplicates;
	u64 faults_injected;
	/* A rescue re-admitted a task the core held with no reference. */
	u64 core_rescues;
	/* A dispatch found the core holding more than the tree and DSQ. */
	u64 core_missing_seen;
	/*
	 * The result of the local DSQ submissions that had no check before:
	 * a refused submission is a task the core declined to place, and it
	 * is re-admitted or counted here instead of being dropped.
	 */
	u64 dsq_refusals;
};

/*
 * Diagnostic trace. The trace is compiled in but disabled unless the
 * loader sets `enable_trace` before load. It records every queue
 * transition, plus one task snapshot that keeps the last transition of
 * each live task. The trace is a ring of a fixed size: once INF_TRACE_CAP
 * records are written the oldest slot is replaced and `overwritten` counts
 * every replacement. A stall campaign reads the ring and the per-task
 * snapshots from the exit dump.
 *
 * `cap`, `next`, `overwritten`, `total` and `enabled` are all written by
 * ops.init(), before the first transition, so the control entry describes
 * the live ring and not only its state at exit. `next` is the number of
 * records written and equals the ring sequence number of the next write.
 * `total` counts every transition and `next` only the ones the ring keeps,
 * so a reader can see how much traffic the ring filtered. The arm step and
 * the exit step are idempotent, so a run that is killed without an exit
 * dump still reports a correct cap.
 *
 * The ring keeps the anomalous transitions: an insert, a pop or a requeue
 * fills the per-task history instead. A ring of INF_TRACE_CAP records is
 * therefore complete for an ordinary campaign, and `overwritten` counts
 * the records a warm ring replaced so an incomplete record is reported as
 * incomplete. The per-task snapshot is the longer-lived record: it keeps
 * each task's last two transitions and its eight-step history, and the
 * table is an LRU of the last INF_TASK_SNAP_MAX distinct tasks. A stalled
 * task that is never traced again is eventually replaced by newer tasks,
 * so a dump taken long after the loss shows the ring and the recent tasks,
 * not the lost one.
 */
#define INF_TRACE_CAP 65536
#define INF_TASK_SNAP_MAX 65536

/*
 * Arena task-context lifetime. The pool is the arena allocator behind
 * scx_task_alloc(); a context is one per live task and is freed by
 * ops.exit_task(). A pool that only grows is a leak, so the scheduler
 * counts every context it allocates and every one it returns, and the
 * loader prints the live value in the periodic stats and at exit.
 *
 * `live` is the number of contexts the scheduler owns right now. `peak` is
 * its high-water mark. `reinits` counts an init_task that found a live
 * context for the task and reused it instead of allocating a second one.
 * `detach_fail` counts an exit that found a queue-node hold still
 * outstanding: the context is not freed below the last hold, so this must
 * stay zero.
 */
struct inf_task_pool {
	u64 live;
	u64 peak;
	u64 inits;
	u64 reinits;
	u64 alloc_fail;
	u64 pool_full;
	u64 frees;
	u64 detach_fail;
	u64 no_ctx;
};

/* One trace operation. The order is stable; the loader names each one. */
#define INF_TR_ENQ_PARK 1
#define INF_TR_ENQ_STALE 2
#define INF_TR_ENQ_INSERT_FAIL 3
#define INF_TR_INSERT 4
#define INF_TR_DEQ_QUEUED 5
#define INF_TR_DEQ_PENDING 6
#define INF_TR_DEQ_REMOVE_FAIL 7
#define INF_TR_DEQ_END 8
#define INF_TR_POP 9
#define INF_TR_POP_STALE 10
#define INF_TR_POP_AFFINITY 11
#define INF_TR_POP_PENDING 12
#define INF_TR_DSQ_OK 13
#define INF_TR_DSQ_REFUSED 14
#define INF_TR_REQUEUE 15
#define INF_TR_REQUEUE_FAIL 16
#define INF_TR_STEAL 17
#define INF_TR_STEAL_SKIP 18
#define INF_TR_REMOVE 19
#define INF_TR_REMOVE_FAIL 20
#define INF_TR_YIELD_TO 21
#define INF_TR_REWEIGHT 22
#define INF_TR_EXIT 23
#define INF_TR_SET_WEIGHT 24
#define INF_TR_DISPATCH_EMPTY 25
#define INF_TR_EXIT_PASS 26
/*
 * Callback-entry records. They are kept in the per-task history only, so a
 * stalled task shows the callbacks that ran and the state each one saw. They
 * are never ringed: they are not anomalous on their own.
 */
#define INF_TR_ENQ_ENTER 27
#define INF_TR_QUIESCENT 28
#define INF_TR_Q_LEAVE 29
#define INF_TR_STOPPING 30
#define INF_TR_RUN_START 31
/*
 * A task was RUNNABLE while its queue node sat in no queue, or in a queue
 * other than the child queue of its own leaf entity. The record is ringed
 * unconditionally, and the causing operation is packed into result.
 */
#define INF_TR_PATH_LOST 32

/* The causal fields of one queue transition. */
struct inf_trace_rec {
	u64 ts;
	u64 seq; /* ring sequence number, monotone */
	u64 slice;
	s64 result;
	s32 pid;
	s32 src_cpu; /* source queue, -1 when the task had none */
	s32 dst_cpu; /* target queue, -1 when there was none */
	u32 op; /* INF_TR_* */
	u32 state; /* enum inf_task_state at the record */
	u32 hold; /* queue node hold count */
	s32 group_cpu;
};

struct inf_trace_ctl {
	u64 next; /* ring records written, including overwritten ones */
	u64 overwritten; /* records replaced in the ring */
	u64 task_overflow; /* task snapshots dropped when the table is full */
	u64 total; /* all transitions seen, ringed or not */
	u32 cap;
	u32 enabled;
};

/*
 * Exit-time queue snapshot, one entry per possible CPU. w_sum is the flat
 * weight sum of revision 3. Revision 4 has no flat sum, so the field
 * stays zero and the loader prints it for the dump layout.
 */
struct inf_queue_snap {
	u64 w_sum;
	u64 head_slice;
	u64 head_weight;
	u64 head_key;
	s64 depth;
	s32 cpu;
	s32 head_pid;
	s32 head_cpu;
	s32 head_group_cpu;
	u32 head_state;
	u32 head_hold;
	u32 online;
	s64 local_nr; /* tasks in this CPU's core local DSQ at exit */
	u32 head_kflags;
	s64 head_ops_state;
	s32 head_runnable_cpu;
	u32 pad;
};

/* Exit-time task snapshot, keyed by pid. The last transition is kept. */
struct inf_task_snap {
	u64 ts;
	u64 slice;
	u64 weight;
	s32 pid;
	s32 queued_cpu;
	s32 group_cpu;
	u32 state;
	u32 hold;
	u32 joined;
	u32 moving;
	u32 reweight_pending;
	u32 dequeue_pending;
	u32 exit_pending;
	u32 last_op;
	s32 last_src;
	s32 last_dst;
	s64 last_result;
	/*
	 * Tree position of the task at the last transition. node_owner is 0
	 * when no queue holds the node, 1 when the child queue of its leaf
	 * entity holds it, and 2 when another queue does. chain_broken counts
	 * the group entities between the leaf and the root that sit outside
	 * their own parent queue, which is the path the selection walks.
	 */
	u32		node_owner;
	u32		leaf_state;
	s64		leaf_count;
	u32		chain_broken;
	u32		path_depth;
	s32		leaf_idx;
	s32		leaf_cpu;
	u64		prev_ts;
	u32		prev_op;
	u32		prev_state;
	s32		prev_src;
	s32		prev_dst;
	s64		prev_result;
	struct inf_hist hist[8];
	u32		hist_count;
	u32		pad;
};

/*
 * Per-task transition trace.
 *
 * This is the lossless record of the callbacks that touch one task. It is
 * wider than the transition ring: every one of the eleven callbacks of the
 * scheduler appends one record that carries the arguments the callback
 * saw and the state of both sides of the boundary:
 *
 * - the scheduler's own state: the entity state, the CPU whose tree holds
 *   the task, the CPU that owns the held path, and whether the queue node
 *   of the task still sits in the child queue of its own leaf entity;
 * - the core's state: the SCX_TASK_* flags, the ops_state machine, the DSQ
 *   the task is on, the CPU the core placed it on, and the holding CPU of
 *   an in-flight move;
 * - the shape of the CPU at that moment: the advisory tree depth and the
 *   core's local DSQ depth.
 *
 * The record is the ground truth a stall report needs. A task that becomes
 * runnable in core custody with no scheduler reference has a last record,
 * and that record names the callback that took the reference away or the
 * callback that should have taken it and did not.
 *
 * The table is a per-pid array limited to INF_TT_SLOTS entries and indexed
 * by the low bits of the pid. An entry belongs to the pid stored in it; the
 * first record of another pid clears the sequence, so a recycled pid never
 * reports the history of its predecessor. INF_TT_CAP records are kept per
 * task and the ring overwrites the oldest one, which the control entry
 * counts.
 *
 * A record that shows the invariant violation below is copied to the
 * frozen table, so it survives both the ring and the table.
 */
#define INF_TT_CAP 32
#define INF_TT_SLOTS 2048
#define INF_TT_FROZEN_MAX 16

/* Extra callback codes of the trace, on top of the INF_CB_* set. */
#define INF_TT_ENQ_RET 0x40 /* ops.enqueue returned */
#define INF_TT_DISP_RET 0x41 /* ops.dispatch returned */
#define INF_TT_TICK_CHECK 0x42 /* a tick-side custody check */
#define INF_TT_DISP_CHECK 0x43 /* a dispatch-side custody check */
#define INF_TT_ENQ_CHECK 0x44 /* an enqueue-side custody check */

/* The queue membership of the node of a task, as the record reads it. */
#define INF_TT_NODE_NONE 0 /* the node is in no queue */
#define INF_TT_NODE_OWN 1 /* the node is in its own leaf queue */
#define INF_TT_NODE_OTHER 2 /* the node is in some other queue */

struct inf_tt_rec {
	u64 ts; /* scx_bpf_now() */
	u64 enq_flags; /* enq_flags of the callback, 0 when it has none */
	u64 deq_flags; /* deq_flags of the callback, 0 when it has none */
	u64 dsq; /* p->scx.dsq, 0 when the task is on no DSQ */
	u64 ops_state; /* p->scx.ops_state.counter */
	s32 pid;
	s32 cb; /* INF_CB_* or INF_TT_* */
	s32 task_cpu; /* p->scx.runnable_cpu, the rq the core queued it on */
	s32 holding_cpu; /* p->scx.holding_cpu */
	s32 queued_cpu; /* the CPU whose tree holds the task, -1 for none */
	s32 path_cpu; /* the CPU that owns the held path, -1 for none */
	u32 scx_flags; /* p->scx.flags */
	u32 ent_state; /* enum inf_task_state of the task context */
	u32 node_owner; /* INF_TT_NODE_* */
	u32 chain_broken; /* group entities outside their own parent queue */
	u32 tree_depth; /* advisory depth of queued_cpu at the record */
	u32 local_nr; /* the core's local DSQ depth of the record CPU */
	u32 rq_nr; /* the core's queued task count of the record CPU */
	u32 ho_pending; /* the task has an in-flight local DSQ handoff */
	s64 last_dsq_ret; /* the last local DSQ submission of the task */
};

struct inf_tt_val {
	u64 next; /* records written, the index of the next one */
	u64 frozen; /* the trace was frozen by a custody check */
	u64 frozen_seq; /* slot of the frozen table, 0 when not frozen */
	s32 pid; /* the task this entry describes */
	u32 detected_cb; /* the check that froze it, 0 while live */
	/*
	 * The first custody-check verdict that did not find a reference, and
	 * how many such verdicts followed. A transient handoff window is
	 * seen once; a task that stays without a reference is seen again
	 * after the window and only then frozen.
	 */
	u64		  lost_first_ns;
	u64		  lost_count;
	struct inf_tt_rec rec[INF_TT_CAP];
};

/*
 * The reason a custody check kept or flagged a task. The value names the
 * state the task was in, so a run reports why the check fired instead of
 * only that it did.
 */
#define INF_TT_WHY_OWNED 0 /* a queue of the task's own leaf holds it */
#define INF_TT_WHY_INFLIGHT 1 /* SELECTED, the local DSQ insert in flight */
#define INF_TT_WHY_NO_CTX 2 /* no task context at all */
#define INF_TT_WHY_UNLINKED 3 /* RUNNABLE, node in no reachable queue */
#define INF_TT_WHY_NO_DSQ 4 /* SELECTED, no DSQ, handoff past its slot */
#define INF_TT_WHY_PARKED 5 /* PARKED or EXITING, an intended handoff */
#define INF_TT_WHY_NO_STATE 6 /* INACTIVE or unknown with custody */
#define INF_TT_WHY_REASONS 8

struct inf_tt_ctl {
	u64 created; /* entries claimed by a new pid */
	u64 checks; /* custody checks that ran */
	u64 scans; /* task lookups of those checks */
	u64 stranded; /* tasks that failed the invariant */
	u64 frozen; /* traces copied to the frozen table */
	u64 canaries; /* CANARY lines written to dmesg */
	u64 overwritten; /* records a per-task ring replaced */
	u64 why[INF_TT_WHY_REASONS]; /* verdicts, indexed by INF_TT_WHY_* */
	u32 cap;
	u32 enabled;
};

/*
 * The first bad unlinks of the entity counts. A count reaches zero while the
 * child queue of the entity still holds nodes: the entity leaves its parent
 * queue and every task below it becomes unreachable, which is the strand.
 * Each entry names the site that removed the child, the entity, its stored
 * count, the number of children it still held, and the task that left.
 */
#define INF_DEPTH_LOSS_MAX 8

/* The site of one count-down, so a bad unlink names its caller. */
#define INF_CD_POP 1 /* a dispatch removed the selected task */
#define INF_CD_LEAVE 2 /* a task left the tree */
#define INF_CD_STEAL 3 /* a steal removed the task from the source */

struct inf_depth_loss {
	u64 ts;
	u64 cgrp_id;
	s32 site;
	s32 pid;
	u32 level;
	u32 idx;
	u32 count;
	u32 nr_children;
	u32 ent_state;
	u32 cpu;
	u32 seq;
};

/*
 * The entity chain of a task that a custody check froze, one entry per group
 * level from the task's leaf parent to the root. A task is reachable from the
 * root only when every entity on its chain is RUNNABLE and sits in the child
 * queue of the entity above it, so one record names the level that broke and
 * whether its count agreed with the children it still held.
 */
struct inf_chain_level {
	u64 cgrp_id;
	u32 idx;
	u32 state;
	u32 count;
	u32 nr_children;
	u32 linked; /* the node is in the child queue of the level above */
	u32 level;
};

struct inf_chain_snap {
	u64		       ts;
	s32		       pid;
	s32		       parent_idx;
	s32		       queued_cpu;
	u32		       node_owner;
	u32		       depth;
	u32		       nr_levels;
	struct inf_chain_level lvl[INF_MAX_LEVELS];
};

/* Controlled-refusal counter for the local DSQ insert regression test. */
struct inf_test_ctl {
	u64 dsq_refuse;
};

/*
 * Controlled refusals for the steal and yield-to tests. The map is empty
 * unless user space arms it, so a normal run never reads a forced verdict.
 * A nonzero counter is the number of decisions to refuse; it is
 * decremented once per decision.
 */
struct inf_fault_ctl {
	u64 steal_dest_refuse; /* refuse one destination revalidation */
	u64 steal_insert_refuse; /* skip one destination leaf insert */
	u64 yield_probe; /* run one synthetic yield-to probe */
	u64 yield_probe_band_refuse; /* make the probe fail its band check */
	u64 yield_probe_running; /* give the probe a running target */
	u64 yield_insert_refuse; /* skip one promotion insert */
	/*
	 * Handoff refusals armed by --test-handoff-fail KIND:COUNT, indexed
	 * by the INF_HO_* kind. One entry is one armed refusal, and the hot
	 * path reads the array only when the loader sets the rodata gate.
	 */
	u64 handoff_fail[8];
};

/*
 * Mirror of lib/cgroup_weight.bpf.c's counter map. A static assertion in
 * main.bpf.c keeps the layout identical to struct
 * scx_cgroup_weight_stats in lib/cgroup_weight.h.
 */
struct inf_cgroup_weight_stats {
	u64 joins;
	u64 leaves;
	u64 reweights;
	u64 moves;
	u64 refolds;
	u64 load_underflows;
	u64 nr_underflows;
	u64 epoch;
	u64 init_idle;
	u64 idle_on;
	u64 idle_off;
};

/* Arguments for the one-shot arena/library init syscall. */
struct inf_arena_init_args {
	u64 static_pages;
	u64 task_ctx_size;
	u64 nr_llcs;
};

#endif /* __SCX_INFINITY_INTF_H */
