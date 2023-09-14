/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#define XDP_TX_METADATA				(1 << 1)

#define XDP_TX_METADATA_TIMESTAMP               (1 << 0)
#define XDP_TX_METADATA_CHECKSUM                (1 << 1)

struct xsk_tx_metadata {
	union {
		struct {
			__u32 flags;

			/* XDP_TX_METADATA_CHECKSUM */

			/* Offset from desc->addr where checksumming should start. */
			__u16 csum_start;
			/* Offset from csum_start where checksum should be stored. */
			__u16 csum_offset;
		};

		struct {
			/* XDP_TX_METADATA_TIMESTAMP */
			__u64 tx_timestamp;
		} completion;
	};
};

struct xdp_umem_reg_v3 {
	__u64 addr;
	__u64 len;
	__u32 chunk_size;
	__u32 headroom;
	__u32 flags;
	__u32 tx_metadata_len;
};
