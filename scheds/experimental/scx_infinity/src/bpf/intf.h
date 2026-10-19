/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared definitions for scx_infinity.
 *
 * The global FIFO skeleton has no scheduling state and no configuration,
 * so this header currently declares nothing. The BPF program and the Rust
 * loader still share it so that the generated bindings exist from the
 * first commit, and the Infinity policy can add its constants and state
 * layouts here later.
 */
#ifndef __SCX_INFINITY_INTF_H
#define __SCX_INFINITY_INTF_H

#endif /* __SCX_INFINITY_INTF_H */
