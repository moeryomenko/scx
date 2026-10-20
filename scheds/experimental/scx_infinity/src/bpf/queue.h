/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The scheduler-owned per-CPU ready queue.
 *
 * sched_ext has no queue that the scheduler can reorder under its own
 * lock, so the ready queue lives in scheduler memory. The default is the
 * eligible deadline queue from lib/edq.h: an intrusive AVL tree with a
 * hold count and exact node removal. The queue-list build feature
 * replaces it with an intrusive FIFO list that exposes the same
 * interface.
 *
 * Both implementations are ordered by the scheduler-owned key. A head key
 * counts down from INF_KEY_MID and a tail key counts up from it, so the
 * newest head insert is first and a tail insert is last.
 */
#pragma once

#include <lib/edq.h>

#ifdef INF_QUEUE_LIST
#include "queue_list.h"

typedef struct inf_list __arena	     inf_queue_t;
typedef struct inf_list_node __arena inf_queue_node_t;
/* A struct member cannot repeat the address space of its type. */
#define INF_QUEUE_NODE_FIELD struct inf_list_node
#else
typedef struct scx_edq __arena	    inf_queue_t;
typedef struct scx_edq_task __arena inf_queue_node_t;
#define INF_QUEUE_NODE_FIELD struct scx_edq_task
#endif

/*
 * Initialize an empty queue and its lock. Called once per possible CPU
 * from the sleepable ops.init().
 */
static __always_inline void inf_queue_init(inf_queue_t *queue)
{
#ifdef INF_QUEUE_LIST
	inf_list_init(queue);
#else
	WRITE_ONCE(queue->root, NULL);
	WRITE_ONCE(queue->first, NULL);
	WRITE_ONCE(queue->first_deadline, 0);
	WRITE_ONCE(queue->min_slice, 0);
	WRITE_ONCE(queue->lock, 0);
	WRITE_ONCE(queue->nr, 0);
	WRITE_ONCE(queue->seq, 0);
#endif
}

static __always_inline int inf_queue_insert(inf_queue_t			 *queue,
					    inf_queue_node_t __arg_arena *node,
					    u64 key, u64 slice)
{
#ifdef INF_QUEUE_LIST
	return inf_list_insert(queue, node, key, slice);
#else
	return scx_edq_insert(queue, node, key, 0, slice);
#endif
}

static __always_inline int inf_queue_remove(inf_queue_t			 *queue,
					    inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	return inf_list_remove(queue, node);
#else
	return scx_edq_remove(queue, node);
#endif
}

static __always_inline int
inf_queue_try_remove(inf_queue_t *queue, inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	return inf_list_try_remove(queue, node);
#else
	return scx_edq_try_remove(queue, node);
#endif
}

/* Pop the head, optionally holding the node across the caller's use. */
static __always_inline u64 inf_queue_pop(inf_queue_t *queue, bool hold)
{
#ifdef INF_QUEUE_LIST
	return inf_list_pop(queue, hold);
#else
	return scx_edq_pop(queue, hold);
#endif
}

/* Hold the head without removing it. */
static __always_inline u64 inf_queue_peek_hold(inf_queue_t *queue)
{
#ifdef INF_QUEUE_LIST
	return inf_list_peek_hold(queue);
#else
	return scx_edq_peek_hold(queue);
#endif
}

static __always_inline void inf_queue_hold(inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	inf_list_node_hold(node);
#else
	scx_edq_task_hold(node);
#endif
}

static __always_inline void inf_queue_drop(inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	inf_list_node_drop(node);
#else
	scx_edq_task_drop(node);
#endif
}

static __always_inline int
inf_queue_node_init(inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	return inf_list_node_init(node);
#else
	return scx_edq_task_init(node);
#endif
}

/*
 * Remove the node from any queue and wait for the last hold to drop. A
 * task context is never freed while a pop or a steal still holds it.
 */
static __always_inline int
inf_queue_node_detach(inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	return inf_list_node_detach(node);
#else
	return scx_edq_task_detach(node);
#endif
}

/* The key the node was inserted with, used to restore a failed move. */
static __always_inline u64 inf_queue_node_key(inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	return node->key;
#else
	return node->node.deadline;
#endif
}

static __always_inline u64 inf_queue_nr(inf_queue_t *queue)
{
#ifdef INF_QUEUE_LIST
	return inf_list_nr(queue);
#else
	return scx_edq_nr_queued(queue);
#endif
}

/*
 * Lockless head for the exit snapshot. The pointer is advisory: it may be
 * stale if the queue changes while the dump runs, which is acceptable for a
 * diagnostic record.
 */
static __always_inline inf_queue_node_t __arg_arena *
inf_queue_first(inf_queue_t *queue)
{
#ifdef INF_QUEUE_LIST
	return queue->head;
#else
	return (inf_queue_node_t *)queue->first;
#endif
}

/* Current hold count, for the trace record. */
static __always_inline u32
inf_queue_node_hold(inf_queue_node_t __arg_arena *node)
{
	if (!node)
		return 0;
	return (u32)node->holdcnt;
}

/* The queue that owns the node, or NULL when it is unlinked. */
static __always_inline inf_queue_t __arg_arena *
inf_queue_node_owner(inf_queue_node_t __arg_arena *node)
{
#ifdef INF_QUEUE_LIST
	return node->owner;
#else
	return node->edq;
#endif
}
