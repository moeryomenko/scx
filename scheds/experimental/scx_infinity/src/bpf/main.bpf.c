/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_infinity global FIFO skeleton.
 *
 * This is the loading and teardown skeleton for the Infinity work, not the
 * Infinity policy. Every task goes to SCX_DSQ_GLOBAL in arrival order with
 * the default slice, so the scheduler is a plain global FIFO. The wakeup
 * path asks the default idle CPU selection for a target and inserts the
 * task into that CPU's local DSQ when the selection is direct.
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Pick a CPU for a waking task and hand it straight to that CPU when the
 * default selection reports an idle target.
 */
s32 BPF_STRUCT_OPS(infinity_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool direct = false;
	s32  cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);
	if (direct)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

/*
 * Send every other task to the global DSQ. The global DSQ is FIFO, so the
 * arrival order is the run order.
 */
void BPF_STRUCT_OPS(infinity_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(infinity_init)
{
	return 0;
}

void BPF_STRUCT_OPS(infinity_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(infinity_ops, .select_cpu = (void *)infinity_select_cpu,
	       .enqueue = (void *)infinity_enqueue,
	       .init = (void *)infinity_init, .exit = (void *)infinity_exit,
	       .flags = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .name  = "infinity");
