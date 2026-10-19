#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
#
# infinity_feature_preflight.sh - machine-readable guest feature check.
#
# This is the harness entry point for the disposable VM. It runs the
# repository preflight in strict JSON mode, so an item that is only known
# from the kernel configuration is BLOCKED. The five required items are:
#
#   sched_ext          CONFIG_SCHED_CLASS_EXT and /sys/kernel/sched_ext
#   bpf_arena          BPF arena allocator and JIT probe
#   cgroup_cpu         cgroup v2 cpu controller and cpu.max
#   cpu_idle           the cpu.idle cgroup file
#   scx_cgroup_cbs     sched_ext cpu.weight, cpu.idle and cpu.max glue
#
# Usage:
#   sudo scheds/experimental/scx_infinity/scripts/infinity_feature_preflight.sh \
#       [--require-vm] [--require-two-numa-nodes]
#
# --require-vm makes a non-VM host BLOCKED. Without it the preflight is
# read-only and also runs on a host.
#
# Output: one JSON object per line. The last line is the summary. Exit
# codes: 0 PASS, 1 BLOCKED, 2 usage error.

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REQUIRE_VM=0
PASSTHROUGH=()

json_line() {
    local -r status="$1"
    local -r detail="$2"

    printf '{"harness":"feature_preflight","event":"summary","status":"%s","check":"summary","detail":"%s","pass":0,"fail":0,"blocked":%s}\n' \
        "$status" "$detail" "$([[ "$status" == "PASS" ]] && printf 0 || printf 1)"
}

usage() {
    printf 'usage: %s [--require-vm] [--require-two-numa-nodes]\n' "${0##*/}"
}

while (($#)); do
    case "$1" in
        --require-vm)
            REQUIRE_VM=1
            ;;
        --require-two-numa-nodes)
            PASSTHROUGH+=(--require-two-numa-nodes)
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if (( REQUIRE_VM )); then
    detected=0
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt --vm 2>/dev/null || true)
        if [[ -n "$virt" && "$virt" != "none" ]]; then
            detected=1
        fi
    else
        vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
        product=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
        case "$vendor $product" in
            *QEMU*|*KVM*|*VMware*|*VirtualBox*|*Xen*|*Amazon*|*Google*|*Microsoft*|*Bochs*)
                detected=1
                ;;
        esac
    fi
    if (( detected == 0 )); then
        json_line BLOCKED "no virtual machine detected; --require-vm is set"
        exit 1
    fi
fi

ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)
if [[ -z "$ROOT" || ! -x "$ROOT/scripts/infinity_vm_preflight.sh" ]]; then
    json_line BLOCKED "repository preflight scripts/infinity_vm_preflight.sh is missing"
    exit 1
fi

exec "$ROOT/scripts/infinity_vm_preflight.sh" --json --strict "${PASSTHROUGH[@]}"
