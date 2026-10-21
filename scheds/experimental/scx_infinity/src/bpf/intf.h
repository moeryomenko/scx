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

/* One tail insertion in every eight normal insertions. */
#define INF_GATE_MASK 7U

/*
 * The maximum number of tree levels, from the leaf parent to the root.
 * The cgroup hierarchy is at most cgroup.max.depth deep, and the kernel
 * limit is 16, so a tree of 16 levels covers every hierarchy.
 */
#define INF_MAX_LEVELS 4

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
 * root, and the service minimum of every level. It is the scratch of one
 * selection and the record of one held path.
 */
struct inf_path {
	u32 ent[INF_MAX_LEVELS];
	u64 vmin[INF_MAX_LEVELS];
	u32 depth;
	u32 pad;
};

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
	u32 pad[2];
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
	u64 stale_requeues;
	u64 stale_skips;
	/* Dispatch outcome and normalizer, for the share diagnosis. */
	u64 disp_pop;
	u64 disp_renew;
	u64 disp_total;
	u64 disp_q;
	/* Revision-4 counters. */
	u64 entity_overflow;
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
};

/*
 * Diagnostic trace. The trace is compiled in but disabled unless the
 * loader sets `enable_trace` before load. It records every queue
 * transition that can lose a runnable task, plus one task snapshot that
 * keeps the last transition of each live task. The trace is a ring: once
 * INF_TRACE_CAP records are written the oldest slot is overwritten and
 * `overwritten` counts every replacement. A stall campaign reads the ring
 * and the snapshots from the exit dump.
 */
#define INF_TRACE_CAP 65536
#define INF_TASK_SNAP_MAX 65536

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
	u32 head_kflags;
	s64 head_ops_state;
	s32 head_runnable_cpu;
	u32 pad;
};

/* Exit-time task snapshot, keyed by pid. The last transition is kept. */
struct inf_task_snap {
	u64		ts;
	u64		slice;
	u64		weight;
	s32		pid;
	s32		queued_cpu;
	s32		group_cpu;
	u32		state;
	u32		hold;
	u32		joined;
	u32		moving;
	u32		reweight_pending;
	u32		dequeue_pending;
	u32		exit_pending;
	u32		last_op;
	s32		last_src;
	s32		last_dst;
	s64		last_result;
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
