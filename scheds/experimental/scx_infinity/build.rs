// SPDX-License-Identifier: GPL-2.0
/*
 * Build helper
 *
 * Adds a warning suppression for the generated kernel header
 * and then builds the BPF object and the userspace bindings.
 */

fn add_bpf_warning_suppression(flag: &str) {
    const KEY: &str = "BPF_EXTRA_CFLAGS_POST_INCL";
    let value = match std::env::var(KEY) {
        Ok(existing) => {
            if existing.split_whitespace().any(|entry| entry == flag) {
                return;
            }
            format!("{existing} {flag}")
        }
        Err(_) => flag.to_owned(),
    };
    /* SAFETY: build script runs single threaded. */
    unsafe {
        std::env::set_var(KEY, value);
    }
}

fn main() {
    let list_queue = std::env::var_os("CARGO_FEATURE_QUEUE_LIST").is_some();

    /* The generated header may warn about declarations. */
    /* The warning is not actionable for this scheduler. */
    add_bpf_warning_suppression("-Wno-missing-declarations");

    let mut builder = scx_cargo::BpfBuilder::new().unwrap();
    if list_queue {
        /* Select the intrusive FIFO prototype in main.bpf.c. */
        builder.add_cflag("-DINF_QUEUE_LIST");
    }
    builder
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/common.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cgroup_bw.bpf.c")
        .add_source("src/bpf/lib/cgroup_weight.bpf.c")
        .add_source("src/bpf/lib/cgroup_ctl.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/edq.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c");
    if list_queue {
        builder.add_source("src/bpf/queue_list.bpf.c");
    }
    builder.compile_link_gen().unwrap();
}
