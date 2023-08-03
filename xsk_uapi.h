/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#define XDP_TX_METADATA				(1 << 1)

#define XDP_TX_METADATA_TIMESTAMP               (1 << 0)
#define XDP_TX_METADATA_CHECKSUM                (1 << 1)

#define XDP_TX_METADATA_LEN			9

struct xsk_tx_metadata {
	__u32 flags;
	__u16 csum_start;
	__u16 csum_offset;
	__u64 tx_timestamp;
};
