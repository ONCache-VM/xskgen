/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#ifndef XDP_TX_METADATA
#define XDP_TX_METADATA				(1 << 1)

#define XDP_TXMD_FLAGS_TIMESTAMP		(1 << 0)
#define XDP_TXMD_FLAGS_CHECKSUM			(1 << 1)
#define XDP_TXMD_FLAGS_SEGMENT_OFFLOAD		(1 << 3)

#define XDP_UMEM_TX_METADATA_LEN	(1 << 2)

struct xsk_tx_metadata {
	__u64 flags;

	union {
		struct {
			/* XDP_TXMD_FLAGS_CHECKSUM */

			/* Offset from desc->addr where checksumming should start. */
			__u16 csum_start;
			/* Offset from csum_start where checksum should be stored. */
			__u16 csum_offset;
			
			/* XDP_TXMD_FLAGS_SEGMENT_OFFLOAD */
			unsigned short	gso_size;
			__u16	len;
			__u16 headlen;

			/* XDP_TXMD_FLAGS_LAUNCH_TIME */
			/* Launch time in nanosecond against the PTP HW Clock */
			__u64 launch_time;

		} request;

		struct {
			/* XDP_TXMD_FLAGS_TIMESTAMP */
			__u64 tx_timestamp;
		} completion;
	};
};

struct xdp_umem_reg {
	__u64 addr;
	__u64 len;
	__u32 chunk_size;
	__u32 headroom;
	__u32 flags;
	__u32 tx_metadata_len;
};
#endif
