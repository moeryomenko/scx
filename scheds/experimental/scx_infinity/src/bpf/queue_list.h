/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intrusive FIFO list prototype for the per-CPU ready queue.
 *
 * This is a measurement prototype, not a second supported policy. It
 * exposes the same operations as lib/edq.h: insert, exact remove, pop,
 * peek, a hold count and a detach that waits for the last hold. It has no
 * key search, so the caller inserts at the front or the back according to
 * the sign of the key relative to INF_KEY_MID.
 *
 * The list keeps the same lifetime rule as EDQ: a pop or peek takes a hold
 * before it releases the queue lock, and a task context is freed only
 * after every hold drops.
 */
#pragma once

#include <scx/common.bpf.h>
#include <bpf_atomic.h>

struct inf_list;
struct inf_list_node;

typedef struct inf_list __arena	     inf_list_t;
typedef struct inf_list_node __arena inf_list_node_t;

#define INF_LIST_DEAD ((struct inf_list __arena *)(unsigned long)1)

struct inf_list_node {
	struct inf_list_node __arena *next;
	struct inf_list_node __arena *prev;
	struct inf_list __arena	     *owner;
	u64			      key;
	s32			      holdcnt;
	u32			      on_list;
	u32			      dead;
	u32			      pad;
};

struct inf_list {
	struct inf_list_node __arena *head;
	struct inf_list_node __arena *tail;
	u32			      lock;
	u32			      pad;
	u64			      nr;
};

static __always_inline int inf_list_lock(inf_list_t __arg_arena *list)
{
	if (!READ_ONCE(list->lock) && cmpxchg(&list->lock, 0, 1) == 0)
		return 0;
	while (can_loop) {
		if (!READ_ONCE(list->lock) && cmpxchg(&list->lock, 0, 1) == 0)
			return 0;
		cpu_relax();
	}
	scx_bpf_error("inf_list: lock timed out");
	return -ETIMEDOUT;
}

static __always_inline int inf_list_trylock(inf_list_t __arg_arena *list)
{
	if (!READ_ONCE(list->lock) && cmpxchg(&list->lock, 0, 1) == 0)
		return 0;
	return -EBUSY;
}

static __always_inline void inf_list_unlock(inf_list_t __arg_arena *list)
{
#if defined(__BPF_FEATURE_LOAD_ACQ_STORE_REL)
	__atomic_store_n(&list->lock, 0, __ATOMIC_RELEASE);
#elif defined(__TARGET_ARCH_x86)
	smp_store_release(&list->lock, 0);
#else
	(void)__sync_lock_test_and_set(&list->lock, 0);
#endif
}

static __always_inline void
inf_list_node_hold(inf_list_node_t __arg_arena *node)
{
	__atomic_add_fetch(&node->holdcnt, 1, 0);
}

static __always_inline void
inf_list_node_drop(inf_list_node_t __arg_arena *node)
{
	__atomic_add_fetch(&node->holdcnt, -1, 0);
}

void inf_list_init(inf_list_t __arg_arena *list);
int  inf_list_insert(inf_list_t __arg_arena	 *list,
		     inf_list_node_t __arg_arena *node, u64 key, u64 slice);
int  inf_list_remove(inf_list_t __arg_arena	 *list,
		     inf_list_node_t __arg_arena *node);
int  inf_list_try_remove(inf_list_t __arg_arena	     *list,
			 inf_list_node_t __arg_arena *node);
u64  inf_list_pop(inf_list_t __arg_arena *list, bool hold);
u64  inf_list_peek_hold(inf_list_t __arg_arena *list);
u64  inf_list_nr(inf_list_t __arg_arena *list);
int  inf_list_node_init(inf_list_node_t __arg_arena *node);
int  inf_list_node_detach(inf_list_node_t __arg_arena *node);
