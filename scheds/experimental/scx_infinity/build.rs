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
    /* The generated header may warn about declarations. */
    /* The warning is not actionable for this scheduler. */
    add_bpf_warning_suppression("-Wno-missing-declarations");

    /*
     * The diagnostic trace is a build feature. The BPF side needs the
     * define, because every call site of the trace is compiled out of
     * the default object: the ring, the per-task snapshots and the
     * custody checks cost verifier instructions in the dispatch and
     * enqueue programs, and neither fits them together with a repair.
     */
    if std::env::var_os("CARGO_FEATURE_TRACE").is_some() {
        add_bpf_warning_suppression("-DINF_DIAG_TRACE=1");
        println!("cargo:rustc-env=SCX_INFINITY_TRACE=1");
    }

    let mut builder = scx_cargo::BpfBuilder::new().unwrap();
    builder
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/common.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cgroup_bw.bpf.c")
        .add_source("src/bpf/lib/cgroup_weight.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/edq.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c");
    builder.compile_link_gen().unwrap();
}
