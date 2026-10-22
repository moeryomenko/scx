/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Unified cgroup control layer: cpu.max from lib/cgroup_bw.bpf.c and
 * hierarchical cpu.weight / cpu.idle from lib/cgroup_weight.bpf.c.
 *
 * The layer owns only two enable bits. It never changes the legacy
 * scx_cgroup_bw_* entry points; it calls them.
 */
#include <scx/common.bpf.h>
#include <lib/cgroup_ctl.h>

static bool  ctl_bw_enabled;
static bool  ctl_weight_enabled;

__hidden int scx_cgroup_ctl_lib_init(struct scx_cgroup_ctl_config *config)
{
	struct scx_cgroup_weight_config weight = {};
	int				ret;

	if (!config)
		return -EINVAL;

	if (config->enable_bw) {
		struct scx_cgroup_bw_config bw = {
			.verbose = config->verbose,
		};

		ret = scx_cgroup_bw_lib_init(&bw);
		if (!ret)
			ctl_bw_enabled = true;
		else if (ret != -EOPNOTSUPP)
			return ret;
		/*
		 * -EOPNOTSUPP means the running kernel has no cpu.max for
		 * sched_ext. Keep the scheduler usable with cpu.weight and
		 * cpu.idle only, as the compatibility contract requires.
		 */
	}

	weight.verbose = config->verbose;
	ret	       = scx_cgroup_weight_lib_init(&weight);
	if (ret)
		return ret;

	ctl_weight_enabled = true;
	return 0;
}

__hidden int
scx_cgroup_ctl_cgroup_init(struct cgroup *cgrp		     __arg_trusted,
			   struct scx_cgroup_init_args *args __arg_trusted)
{
	int ret;

	if (ctl_bw_enabled) {
		ret = scx_cgroup_bw_init(cgrp, args);
		if (ret)
			return ret;
	}

	if (ctl_weight_enabled)
		return scx_cgroup_weight_init(cgrp, args);

	return 0;
}

__hidden void scx_cgroup_ctl_cgroup_exit(struct cgroup *cgrp __arg_trusted)
{
	if (ctl_bw_enabled)
		scx_cgroup_bw_exit(cgrp);
	if (ctl_weight_enabled)
		scx_cgroup_weight_exit(cgrp);
}

__hidden void scx_cgroup_ctl_set_weight(struct cgroup *cgrp __arg_trusted,
					u32		    weight)
{
	if (ctl_weight_enabled)
		scx_cgroup_weight_set_weight(cgrp, weight);
}

__hidden void scx_cgroup_ctl_set_idle(struct cgroup *cgrp __arg_trusted,
				      bool		  idle)
{
	if (ctl_weight_enabled)
		scx_cgroup_weight_set_idle(cgrp, idle);
}

__hidden int scx_cgroup_ctl_set_bandwidth(struct cgroup *cgrp __arg_trusted,
					  u64 period_us, u64 quota_us,
					  u64 burst_us)
{
	if (!ctl_bw_enabled)
		return 0;

	return scx_cgroup_bw_set(cgrp, period_us, quota_us, burst_us);
}

__hidden int scx_cgroup_ctl_move(struct task_struct *p __arg_trusted, u64 taskc,
				 struct cgroup *from __arg_trusted,
				 struct cgroup *to __arg_trusted, s32 cpu,
				 u64 base_weight, bool queued)
{
	int ret = 0;

	if (ctl_bw_enabled)
		ret = scx_cgroup_bw_move(p, taskc, from, to);

	if (!ret && ctl_weight_enabled && queued)
		scx_cgroup_weight_move(from, to, cpu, base_weight);

	return ret;
}

__hidden int scx_cgroup_ctl_throttled(struct task_struct *p __arg_trusted,
				      u64		    taskc)
{
	if (!ctl_bw_enabled)
		return 0;

	return scx_cgroup_bw_throttled(p, taskc);
}

__hidden int scx_cgroup_ctl_put_aside(struct task_struct *p __arg_trusted,
				      u64 taskc, u64 vtime)
{
	if (!ctl_bw_enabled)
		return -EOPNOTSUPP;

	return scx_cgroup_bw_put_aside(p, taskc, vtime);
}

__hidden int scx_cgroup_ctl_reenqueue(void)
{
	if (!ctl_bw_enabled)
		return 0;

	return scx_cgroup_bw_reenqueue();
}

__hidden int scx_cgroup_ctl_consume(struct task_struct *p __arg_trusted,
				    u64 taskc, u64 consumed_ns)
{
	if (!ctl_bw_enabled)
		return 0;

	return scx_cgroup_bw_consume(p, taskc, consumed_ns);
}

__hidden int scx_cgroup_ctl_cancel(u64 taskc, u64 flags)
{
	if (!ctl_bw_enabled)
		return 0;

	return scx_cgroup_bw_cancel(taskc, flags);
}

__hidden int scx_cgroup_ctl_weight(struct task_struct *p __arg_trusted, s32 cpu,
				   bool				  joining,
				   struct scx_cgroup_weight_info *out)
{
	if (!ctl_weight_enabled && out) {
		out->weight = p && p->scx.weight ? p->scx.weight : 1;
		out->scale  = SCX_CGROUP_WEIGHT_ONE;
		out->idle   = 0;
		return 0;
	}

	return scx_cgroup_weight_task(p, cpu, joining, out);
}

__hidden int scx_cgroup_ctl_weight_fold(struct cgroup *cgrp __arg_trusted,
					s32 cpu, u64 base_weight, bool joining,
					struct scx_cgroup_weight_info *out)
{
	if (!ctl_weight_enabled && out) {
		out->weight = base_weight ? base_weight : 1;
		out->scale  = SCX_CGROUP_WEIGHT_ONE;
		out->idle   = 0;
		return 0;
	}

	return scx_cgroup_weight_fold(cgrp, cpu, base_weight, joining, out);
}

__hidden int scx_cgroup_ctl_weight_refresh(struct task_struct *p __arg_trusted,
					   s32 cpu, u64 base_weight,
					   struct scx_cgroup_weight_info *out)
{
	if (!ctl_weight_enabled && out) {
		out->weight = base_weight ? base_weight : 1;
		out->scale  = SCX_CGROUP_WEIGHT_ONE;
		out->idle   = 0;
		return 0;
	}

	return scx_cgroup_weight_refresh(p, cpu, base_weight, out);
}

__hidden u64 scx_cgroup_ctl_epoch(void)
{
	if (!ctl_weight_enabled)
		return 0;

	return scx_cgroup_weight_epoch();
}

__hidden void scx_cgroup_ctl_join(struct task_struct *p __arg_trusted, s32 cpu,
				  u64 base_weight)
{
	if (ctl_weight_enabled)
		scx_cgroup_weight_join(p, cpu, base_weight);
}

__hidden void scx_cgroup_ctl_leave(struct task_struct *p __arg_trusted, s32 cpu,
				   u64 base_weight)
{
	if (ctl_weight_enabled)
		scx_cgroup_weight_leave(p, cpu, base_weight);
}

__hidden void scx_cgroup_ctl_reweight(struct task_struct *p __arg_trusted,
				      s32 cpu, u64 old_weight, u64 new_weight)
{
	if (ctl_weight_enabled)
		scx_cgroup_weight_reweight(p, cpu, old_weight, new_weight);
}
