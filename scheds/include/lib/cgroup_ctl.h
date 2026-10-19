/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Unified shared cgroup control API.
 *
 * The bandwidth half is the existing `lib/cgroup_bw.bpf.c` (cpu.max) and its
 * public header lib/cgroup.h. The weight half is lib/cgroup_weight.h. This
 * header and lib/cgroup_ctl.bpf.c tie them together behind one set of hooks,
 * so a scheduler implements cgroup_init/exit/move once and gets cpu.weight,
 * cpu.idle and cpu.max.
 *
 * The legacy `scx_cgroup_bw_*` symbols and the whole of lib/cgroup.h are
 * unchanged. Schedulers that use them directly, scx_lavd and scx_mavd, need
 * no source change; the aliases below only let new code reach the bandwidth
 * half through this header.
 */
#pragma once

#include <lib/cgroup.h>
#include <lib/cgroup_weight.h>

struct scx_cgroup_ctl_config {
	int verbose;
	/* Enforce cpu.max. Userspace clears it when the kernel lacks support. */
	bool enable_bw;
};

/*
 * Compile-time aliases for the bandwidth half. They keep the established
 * scx_cgroup_bw_* contract reachable from a scheduler that includes this
 * header instead of lib/cgroup.h.
 */
#define scx_cgroup_ctl_bw_lib_init scx_cgroup_bw_lib_init
#define scx_cgroup_ctl_bw_init scx_cgroup_bw_init
#define scx_cgroup_ctl_bw_exit scx_cgroup_bw_exit
#define scx_cgroup_ctl_bw_set scx_cgroup_bw_set
#define scx_cgroup_ctl_bw_throttled scx_cgroup_bw_throttled
#define scx_cgroup_ctl_bw_put_aside scx_cgroup_bw_put_aside
#define scx_cgroup_ctl_bw_reenqueue scx_cgroup_bw_reenqueue
#define scx_cgroup_ctl_bw_consume scx_cgroup_bw_consume
#define scx_cgroup_ctl_bw_cancel scx_cgroup_bw_cancel
#define scx_cgroup_ctl_bw_move scx_cgroup_bw_move

int scx_cgroup_ctl_lib_init(struct scx_cgroup_ctl_config *config);

int scx_cgroup_ctl_cgroup_init(struct cgroup *cgrp		 __arg_trusted,
			       struct scx_cgroup_init_args *args __arg_trusted);
void scx_cgroup_ctl_cgroup_exit(struct cgroup *cgrp __arg_trusted);
void scx_cgroup_ctl_set_weight(struct cgroup *cgrp __arg_trusted, u32 weight);
void scx_cgroup_ctl_set_idle(struct cgroup *cgrp __arg_trusted, bool idle);
int  scx_cgroup_ctl_set_bandwidth(struct cgroup *cgrp __arg_trusted,
				  u64 period_us, u64 quota_us, u64 burst_us);

/*
 * Move @p between cgroups. @taskc is the per-task context for the bandwidth
 * cache. @base_weight and @cpu describe the weight contribution only when
 * @queued is set; otherwise the task is not accounted in a group.
 */
int  scx_cgroup_ctl_move(struct task_struct *p __arg_trusted, u64 taskc,
			 struct cgroup *from __arg_trusted,
			 struct cgroup *to __arg_trusted, s32 cpu,
			 u64 base_weight, bool queued);

int  scx_cgroup_ctl_throttled(struct task_struct *p __arg_trusted, u64 taskc);
int  scx_cgroup_ctl_put_aside(struct task_struct *p __arg_trusted, u64 taskc,
			      u64 vtime);
int  scx_cgroup_ctl_reenqueue(void);
int  scx_cgroup_ctl_consume(struct task_struct *p __arg_trusted, u64 taskc,
			    u64 consumed_ns);
int  scx_cgroup_ctl_cancel(u64 taskc, u64 flags);

int  scx_cgroup_ctl_weight(struct task_struct *p __arg_trusted, s32 cpu,
			   bool joining, struct scx_cgroup_weight_info *out);
int  scx_cgroup_ctl_weight_fold(struct cgroup *cgrp __arg_trusted, s32 cpu,
				u64 base_weight, bool joining,
				struct scx_cgroup_weight_info *out);
void scx_cgroup_ctl_join(struct task_struct *p __arg_trusted, s32 cpu,
			 u64 base_weight);
void scx_cgroup_ctl_leave(struct task_struct *p __arg_trusted, s32 cpu,
			  u64 base_weight);
void scx_cgroup_ctl_reweight(struct task_struct *p __arg_trusted, s32 cpu,
			     u64 old_weight, u64 new_weight);
