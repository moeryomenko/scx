/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intrusive FIFO list prototype. See queue_list.h for the contract and
 * the feature note in README.md for the scope.
 */
#include <scx/common.bpf.h>
#include "intf.h"
#include "queue_list.h"

void inf_list_init(inf_list_t __arg_arena *list)
{
	WRITE_ONCE(list->head, NULL);
	WRITE_ONCE(list->tail, NULL);
	WRITE_ONCE(list->lock, 0);
	WRITE_ONCE(list->nr, 0);
}

static __always_inline void unlink_node(inf_list_t __arg_arena	    *list,
					inf_list_node_t __arg_arena *node)
{
	if (node->prev)
		node->prev->next = node->next;
	else
		list->head = node->next;
	if (node->next)
		node->next->prev = node->prev;
	else
		list->tail = node->prev;
	WRITE_ONCE(node->next, NULL);
	WRITE_ONCE(node->prev, NULL);
}

__weak int inf_list_insert(inf_list_t __arg_arena      *list,
			   inf_list_node_t __arg_arena *node, u64 key,
			   u64 slice)
{
	int ret;

	(void)slice;

	ret = inf_list_lock(list);
	if (ret)
		return ret;
	if (READ_ONCE(node->dead)) {
		inf_list_unlock(list);
		return -ECANCELED;
	}
	if (READ_ONCE(node->on_list)) {
		inf_list_unlock(list);
		return -EALREADY;
	}

	node->key = key;
	WRITE_ONCE(node->next, NULL);
	WRITE_ONCE(node->prev, NULL);

	/* A head key is below INF_KEY_MID, so the newest head runs first. */
	if (key < INF_KEY_MID) {
		node->next = list->head;
		if (list->head)
			list->head->prev = node;
		list->head = node;
		if (!list->tail)
			list->tail = node;
	} else {
		node->prev = list->tail;
		if (list->tail)
			list->tail->next = node;
		list->tail = node;
		if (!list->head)
			list->head = node;
	}

	/*
	 * Claim ownership after the link. A concurrent detach sets dead and
	 * either unlinks the node itself or wins the NULL-to-DEAD exchange, so
	 * the two writers serialize on the owner pointer.
	 */
	if (cmpxchg(&node->owner, 0, list)) {
		unlink_node(list, node);
		inf_list_unlock(list);
		return -EALREADY;
	}
	WRITE_ONCE(node->on_list, 1);
	list->nr++;
	inf_list_unlock(list);
	return 0;
}

__weak int inf_list_remove(inf_list_t __arg_arena      *list,
			   inf_list_node_t __arg_arena *node)
{
	int ret;

	ret = inf_list_lock(list);
	if (ret)
		return ret;
	if (!READ_ONCE(node->on_list) || READ_ONCE(node->owner) != list) {
		inf_list_unlock(list);
		return -EINVAL;
	}
	unlink_node(list, node);
	WRITE_ONCE(node->owner, NULL);
	WRITE_ONCE(node->on_list, 0);
	if (list->nr)
		list->nr--;
	inf_list_unlock(list);
	return 0;
}

__weak int inf_list_try_remove(inf_list_t __arg_arena	   *list,
			       inf_list_node_t __arg_arena *node)
{
	int ret;

	ret = inf_list_trylock(list);
	if (ret)
		return ret;
	if (!READ_ONCE(node->on_list) || READ_ONCE(node->owner) != list) {
		inf_list_unlock(list);
		return -EINVAL;
	}
	unlink_node(list, node);
	WRITE_ONCE(node->owner, NULL);
	WRITE_ONCE(node->on_list, 0);
	if (list->nr)
		list->nr--;
	inf_list_unlock(list);
	return 0;
}

__weak u64 inf_list_pop(inf_list_t __arg_arena *list, bool hold)
{
	inf_list_node_t *node;
	int		 ret;

	ret = inf_list_lock(list);
	if (ret)
		return 0;
	node = list->head;
	if (!node) {
		inf_list_unlock(list);
		return 0;
	}
	if (hold)
		inf_list_node_hold(node);
	unlink_node(list, node);
	WRITE_ONCE(node->owner, NULL);
	WRITE_ONCE(node->on_list, 0);
	if (list->nr)
		list->nr--;
	inf_list_unlock(list);
	return (u64)node;
}

__weak u64 inf_list_peek_hold(inf_list_t __arg_arena *list)
{
	inf_list_node_t *node;
	int		 ret;

	ret = inf_list_lock(list);
	if (ret)
		return 0;
	node = list->head;
	if (node)
		inf_list_node_hold(node);
	inf_list_unlock(list);
	return (u64)node;
}

__weak u64 inf_list_nr(inf_list_t __arg_arena *list)
{
	return READ_ONCE(list->nr);
}

__weak int inf_list_node_init(inf_list_node_t __arg_arena *node)
{
	WRITE_ONCE(node->next, NULL);
	WRITE_ONCE(node->prev, NULL);
	WRITE_ONCE(node->owner, NULL);
	WRITE_ONCE(node->key, 0);
	WRITE_ONCE(node->holdcnt, 0);
	WRITE_ONCE(node->on_list, 0);
	WRITE_ONCE(node->dead, 0);
	return 0;
}

/*
 * End the node's queue membership and wait for every hold to drop. The
 * dead flag stops a later insert from reusing the node while the caller
 * frees the task context.
 */
__weak int inf_list_node_detach(inf_list_node_t __arg_arena *node)
{
	volatile int holdcnt;
	inf_list_t  *list;
	int	     ret;

	WRITE_ONCE(node->dead, 1);
	while (can_loop) {
		list = READ_ONCE(node->owner);
		if (!list) {
			if (!cmpxchg(&node->owner, 0, INF_LIST_DEAD))
				break;
			continue;
		}
		if (list == INF_LIST_DEAD)
			break;
		ret = inf_list_lock(list);
		if (ret)
			return ret;
		if (READ_ONCE(node->owner) != list) {
			inf_list_unlock(list);
			continue;
		}
		if (READ_ONCE(node->on_list)) {
			unlink_node(list, node);
			WRITE_ONCE(node->on_list, 0);
			if (list->nr)
				list->nr--;
		}
		WRITE_ONCE(node->owner, NULL);
		inf_list_unlock(list);
		break;
	}
	while ((holdcnt = READ_ONCE(node->holdcnt)) > 0 && can_loop)
		cpu_relax();
	return holdcnt > 0 ? -E2BIG : 0;
}
