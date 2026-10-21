/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The per-parent child queue of the entity tree.
 *
 * Every level of the tree is an eligible deadline queue from lib/edq.h.
 * The queue is ordered by the normalized service value of its children:
 * the service value is the EDQ deadline and the EDQ sequence breaks an
 * equal-service tie. A child leaves with an exact node removal, and a hold
 * keeps a child alive across the gap between two queue locks.
 *
 * The intrusive FIFO list prototype of revision 3 is gone. Its insert used
 * the key only to choose the head or the tail, so it has no key search and
 * cannot order a child queue by service. It is not a hierarchy backend.
 */
#pragma once

#include <lib/edq.h>

/*
 * Initialize an empty queue and its lock. Called once per group entity
 * when the entity is created.
 */
static __always_inline void inf_queue_init(scx_edq_t *queue)
{
	WRITE_ONCE(queue->root, NULL);
	WRITE_ONCE(queue->first, NULL);
	WRITE_ONCE(queue->first_deadline, 0);
	WRITE_ONCE(queue->min_slice, 0);
	WRITE_ONCE(queue->lock, 0);
	WRITE_ONCE(queue->nr, 0);
	WRITE_ONCE(queue->seq, 0);
}

/*
 * Insert a child with @v as its service value. The eligibility and the
 * slice fields carry no policy meaning in this tree.
 */
static __always_inline int inf_queue_insert(scx_edq_t		*queue,
					    scx_edq_task_t __arg_arena *node,
					    u64				v)
{
	return scx_edq_insert(queue, node, v, 0, 0);
}

/*
 * Remove a child. A busy queue lock is retried with the blocking variant,
 * because a queue lock is never held across a callback and a failed
 * remove here would strand a runnable task.
 */
static __always_inline int inf_queue_remove(scx_edq_t		*queue,
					    scx_edq_task_t __arg_arena *node)
{
	int ret = scx_edq_try_remove(queue, node);

	if (ret == -EBUSY)
		ret = scx_edq_remove(queue, node);
	return ret;
}

/* Hold a child without removing it. */
static __always_inline void inf_queue_hold(scx_edq_task_t __arg_arena *node)
{
	scx_edq_task_hold(node);
}

/* Drop a hold taken by inf_queue_hold() or by a queue peek. */
static __always_inline void inf_queue_drop(scx_edq_task_t __arg_arena *node)
{
	scx_edq_task_drop(node);
}

/* Bring a freshly allocated child to the state of one in no queue. */
static __always_inline int inf_queue_node_init(scx_edq_task_t __arg_arena *node)
{
	return scx_edq_task_init(node);
}

/*
 * Remove a child from any queue and wait for the last hold to drop. A
 * task context is never freed while a selection or a steal still holds it.
 */
static __always_inline int inf_queue_node_detach(scx_edq_task_t __arg_arena *node)
{
	return scx_edq_task_detach(node);
}

/* The number of children in the queue. */
static __always_inline u64 inf_queue_nr(scx_edq_t *queue)
{
	return scx_edq_nr_queued(queue);
}

/*
 * The task that owns the node. The node sits at offset 0 of a group entity
 * and at a fixed offset of a task context, so the task pointer names the
 * entity or the context.
 */
static __always_inline scx_edq_task_t *inf_queue_node_task(scx_edq_node_t *node)
{
	return (scx_edq_task_t *)((u64)node -
				  offsetof(struct scx_edq_task, node));
}

/*
 * The next node of a queue in deadline order. The queue is locked while
 * the caller walks, so the tree is stable.
 */
static __always_inline scx_edq_node_t *inf_queue_next(scx_edq_node_t *node)
{
	scx_edq_node_t *p;

	if (node->right) {
		p = node->right;
		while (p->left && can_loop)
			p = p->left;
		return p;
	}

	p = node->parent;
	while (p && p->right == node && can_loop) {
		node = p;
		p = p->parent;
	}
	return p;
}

/* Take and release the lock of a queue. */
static __always_inline int inf_queue_lock(scx_edq_t *queue)
{
	return scx_edq_lock(queue);
}

static __always_inline void inf_queue_unlock(scx_edq_t *queue)
{
	scx_edq_unlock(queue);
}

/*
 * The queue that owns the node, or NULL when the node is unlinked. The
 * membership is the source of truth for a child that is in a queue.
 */
static __always_inline scx_edq_t *inf_queue_node_owner(scx_edq_task_t __arg_arena *node)
{
	return node->edq;
}

/* Current hold count, for the trace record. */
static __always_inline u32 inf_queue_node_hold(scx_edq_task_t __arg_arena *node)
{
	if (!node)
		return 0;
	return (u32)node->holdcnt;
}

/*
 * Unlink a child from whatever queue holds it, without marking the node
 * dead.
 *
 * inf_queue_node_detach() is the teardown primitive: it marks the node dead
 * and no later insert can claim it, because scx_edq_insert() refuses a dead
 * membership with -ECANCELED. A repair of a live node therefore needs the
 * plain removal of the queue that owns it.
 *
 * A node that a teardown already detached carries the dead membership and
 * holds no queue. Its links are rebuilt so that the node can be inserted
 * again.
 */
static __always_inline int inf_queue_unlink(scx_edq_task_t __arg_arena *node)
{
	scx_edq_t *owner = inf_queue_node_owner(node);

	if (owner == (scx_edq_t *)SCX_EDQ_DEAD)
		return inf_queue_node_init(node);
	if (!owner)
		return 0;
	return inf_queue_remove(owner, node);
}
