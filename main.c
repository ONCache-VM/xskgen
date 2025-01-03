// SPDX-License-Identifier: GPL-2.0

/* Send out AF_XDP frames AFAP from a single queue. */

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <libgen.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <bpf/bpf.h>

#include "csum.h"
#include "xsk.h"
#include "xsk_uapi.h"

#define UMEM_FRAME_SIZE		4096 /* PAGE_SIZE */

#define DUMP_EVERY		10000000
#define NSEC_PER_SEC		1000000000ULL
#define NSEC_PER_USEC		1000ULL

#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#endif

#ifndef BPF_EXIT_INSN
#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })
#endif

static bool debug;
static bool fill_meta;
static bool fill_csum = true;
static bool fill_tstamp = true;
static bool request_meta;
static int batch_size = 256;
static bool busy_poll;
static int pkt_size = 1400;
static __u32 ring_size = 1024;
static int umem_size = 2048;

struct xsk {
	int fd;
	void *umem_area;

	struct xsk_umem *umem;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;
	struct xsk_socket *socket;
};

const char *ifname;
static __u8 smac[ETH_ALEN];
static __u8 dmac[ETH_ALEN];
static struct in6_addr saddr;
static struct in6_addr daddr;
static __u16 sport;
static __u16 dport;

static int open_xsk(int ifindex, struct xsk *xsk, __u32 qid, int bind_flags)
{
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	struct xsk_ring_prod *fill = &xsk->fill;
	struct xsk_ring_cons *comp = &xsk->comp;
	struct xsk_ring_prod *tx = &xsk->tx;
	struct xsk_ring_cons *rx = &xsk->rx;
	struct xdp_mmap_offsets off = {};
	struct sockaddr_xdp sxdp = {};
	struct xdp_umem_reg mr = {};
	socklen_t optlen;
	int optval;
	void *map;
	int err;

	/* allocate socket */

	xsk->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (xsk->fd < 0)
		return -errno;

	/* map umem */

	xsk->umem_area = mmap(NULL, umem_size * UMEM_FRAME_SIZE, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
	if (xsk->umem_area == MAP_FAILED)
		return -ENOMEM;

	mr.addr = (uintptr_t)xsk->umem_area;
	mr.len = umem_size * UMEM_FRAME_SIZE;
	mr.chunk_size = UMEM_FRAME_SIZE;
	mr.headroom = 0;
	mr.flags = 0;

	if (fill_meta) {
		/* specify tx metadata size */
		mr.tx_metadata_len = sizeof(struct xsk_tx_metadata);
	}

	err = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
	if (err)
		return -errno;

	/* allocate fill & completion rings */

	err = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size, sizeof(ring_size));
	if (err)
		return -errno;

	err = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size, sizeof(ring_size));
	if (err)
		return -errno;

	/* allocate rx & tx rings */

	err = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &ring_size, sizeof(ring_size));
	if (err)
		return -errno;

	err = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &ring_size, sizeof(ring_size));
	if (err)
		return -errno;

	/* setup the rings */

	optlen = sizeof(off);
	err = getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
	if (err)
		return -errno;

	map = mmap(NULL, off.fr.desc + ring_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_UMEM_PGOFF_FILL_RING);
	if (map == MAP_FAILED)
		return -errno;

	fill->mask = ring_size - 1;
	fill->size = ring_size;
	fill->producer = map + off.fr.producer;
	fill->consumer = map + off.fr.consumer;
	fill->flags = map + off.fr.flags;
	fill->ring = map + off.fr.desc;
	fill->cached_cons = ring_size;

	map = mmap(NULL, off.cr.desc + ring_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_UMEM_PGOFF_COMPLETION_RING);

	comp->mask = ring_size - 1;
	comp->size = ring_size;
	comp->producer = map + off.cr.producer;
	comp->consumer = map + off.cr.consumer;
	comp->flags = map + off.cr.flags;
	comp->ring = map + off.cr.desc;

	map = mmap(NULL, off.rx.desc +
		   ring_size * sizeof(struct xdp_desc),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_PGOFF_RX_RING);
	if (map == MAP_FAILED)
		return -errno;

	rx->mask = ring_size - 1;
	rx->size = ring_size;
	rx->producer = map + off.rx.producer;
	rx->consumer = map + off.rx.consumer;
	rx->flags = map + off.rx.flags;
	rx->ring = map + off.rx.desc;
	rx->cached_prod = *rx->producer;
	rx->cached_cons = *rx->consumer;

	map = mmap(NULL, off.tx.desc +
		   ring_size * sizeof(struct xdp_desc),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_PGOFF_TX_RING);
	if (map == MAP_FAILED)
		return -errno;

	tx->mask = ring_size - 1;
	tx->size = ring_size;
	tx->producer = map + off.tx.producer;
	tx->consumer = map + off.tx.consumer;
	tx->flags = map + off.tx.flags;
	tx->ring = map + off.tx.desc;
	tx->cached_prod = *tx->producer;
	tx->cached_cons = *tx->consumer + ring_size;

	if (busy_poll) {
		/* enable busy poll */

		optval = 1;
		if (setsockopt(xsk->fd, SOL_SOCKET, SO_PREFER_BUSY_POLL,
			       &optval, sizeof(optval)) < 0)
			return -errno;

		optval = 20;
		if (setsockopt(xsk->fd, SOL_SOCKET, SO_BUSY_POLL,
			       &optval, sizeof(optval)) < 0)
			return -errno;

		optval = batch_size;
		if (setsockopt(xsk->fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET,
			       &optval, sizeof(optval)) < 0)
			return -errno;
	}

	/* bind the socket */

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_flags = bind_flags;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = qid;

	err = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	if (err)
		return -errno;

	return 0;
}

static int dummy_rx(int ifindex)
{
	struct bpf_insn prog[] = {
		/* return XDP_PASS; */
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
	};
	int prog_fd;

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL-2.0", prog, 2, NULL);
	if (prog_fd < 0)
		return prog_fd;

	(void)bpf_xdp_detach(ifindex, 0, NULL);
	return bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE | XDP_FLAGS_REPLACE, NULL);
}

static void fill_packet(struct xsk *xsk, __u32 idx)
{
	struct xsk_tx_metadata *meta;
	struct ipv6hdr *ip6h = NULL;
	struct xdp_desc *tx_desc;
	struct udphdr *udph;
	struct ethhdr *eth;
	void *data;
	int ret;
	int len;

	tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
	tx_desc->addr = idx * UMEM_FRAME_SIZE;
	if (fill_meta)
		tx_desc->addr += sizeof(struct xsk_tx_metadata);
	data = xsk_umem__get_data(xsk->umem_area, tx_desc->addr);

	if (fill_meta) {
		meta = data - sizeof(struct xsk_tx_metadata);
		memset(meta, 0, sizeof(*meta));
	}

	eth = data;
	memcpy(eth->h_dest, dmac, ETH_ALEN);
	memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	ip6h = (void *)(eth + 1);
	ip6h->version = 6;
	ip6h->payload_len = htons(sizeof(*udph) + pkt_size);
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = 255;
	ip6h->saddr = saddr;
	ip6h->daddr = daddr;

	udph = (void *)(ip6h + 1);
	udph->source = htons(sport);
	udph->dest = htons(dport);
	udph->len = ip6h->payload_len;

	udph->check = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
				       ntohs(udph->len), IPPROTO_UDP, 0);

	memset((void *)(udph + 1), (__u8)idx, pkt_size);

	if (fill_meta) {
		if (fill_csum) {
			meta->flags |= XDP_TXMD_FLAGS_CHECKSUM;
			meta->request.csum_start = sizeof(*eth) + sizeof(*ip6h);
			meta->request.csum_offset = offsetof(struct udphdr, check);
		}

		if (fill_tstamp)
			meta->flags = XDP_TXMD_FLAGS_TIMESTAMP;

		if (request_meta)
			tx_desc->options |= XDP_TX_METADATA;
	} else {
		udph->check = csum_fold(csum_partial(udph, sizeof(*udph) + pkt_size, 0));
	}
	tx_desc->len = ETH_HLEN + sizeof(*ip6h) + sizeof(*udph) + pkt_size;
}

static void populate_umem(struct xsk *xsk)
{
	__u32 i;

	for (i = 0; i < umem_size; i++)
		fill_packet(xsk, i);
}

static void close_xsk(struct xsk *xsk)
{
	munmap(xsk->umem_area, umem_size * UMEM_FRAME_SIZE);
	close(xsk->fd);
}

static int kick_tx(struct xsk *xsk)
{
	return sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static __u32 submit_tx(struct xsk *xsk, int batch)
{
	__u32 idx = 0;
	__u32 got;

	got = xsk_ring_prod__reserve(&xsk->tx, batch_size, &idx);
	if (debug)
		printf("submit_idx idx=%u\n", idx);

	if (got > 0)
		xsk_ring_prod__submit(&xsk->tx, got);
	return got;
}

static __u32 complete_tx(struct xsk *xsk)
{
	__u32 idx = 0;
	__u32 got;

	got = xsk_ring_cons__peek(&xsk->comp, batch_size, &idx);
	if (debug)
		printf("complete_tx idx=%u\n", idx);
	if (!got)
		return 0;

	xsk_ring_cons__release(&xsk->comp, got);

	return got;
}

static void generate_tx(struct xsk *xsk, long long limit)
{
	struct timeval tv_start, tv_now;
	__u64 sent_since_last_dump = 0;
	int outstanding = ring_size;
	__u32 complete, sent;
	struct pollfd fds[2];
	int ret;

	fds[0].fd = xsk->fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	fds[1].fd = STDIN_FILENO;
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	gettimeofday(&tv_start, NULL);

	int i = 0;

	while (limit != 0) {
		sent = 0;
		if (outstanding > 0) {
			sent = submit_tx(xsk, batch_size);
			if (!busy_poll && sent) {
				ret = kick_tx(xsk);
				if (ret)
					error(1, -errno, "kick_tx");
			}
			outstanding -= sent;
		}

		fds[0].revents = 0;
		ret = poll(fds, 2, 1000);
		if (ret < 0)
			break;

		if (fds[1].revents)
			break;

		if (!(fds[0].revents & POLLOUT)) {
			if (debug) {
				printf("spin! outstanding=%d\n", outstanding);
				usleep(1000 * 1000);
			}
			continue;
		}

		complete = complete_tx(xsk);
		if (complete) {
			outstanding += complete;

			if (limit >= 0) {
				limit -= complete;
				if (limit < 0)
					limit = 0;
			}
		}
		sent_since_last_dump += complete;

		if (debug)
			printf("sent=%u complete=%u\n", sent, complete);

		if (sent_since_last_dump >= DUMP_EVERY) {
			__u64 total_bits;
			double elapsed;
			__u64 start;
			__u64 now;

			total_bits = (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + pkt_size) * 8;
			total_bits *= sent_since_last_dump;

			gettimeofday(&tv_now, NULL);

			now = tv_now.tv_sec * NSEC_PER_SEC + tv_now.tv_usec * NSEC_PER_USEC;
			start = tv_start.tv_sec * NSEC_PER_SEC + tv_start.tv_usec * NSEC_PER_USEC;
			elapsed = (double)(now - start) / NSEC_PER_SEC;

			printf("sent %llu packets %llu bits, took %f sec, %f gbps %f mpps\n",
			       sent_since_last_dump,
			       total_bits,
			       elapsed,
			       total_bits / elapsed / 1000 / 1000 / 1000,
			       sent_since_last_dump / elapsed / 1000 / 1000);

			sent_since_last_dump = 0;

			gettimeofday(&tv_start, NULL);
		}

		if (debug)
			usleep(1000 * 1000);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] <ifname> <src mac> <dst mac> <src ip> <dst ip> <src port> <dst port>\n"
		"OPTS:\n"
		"    -b    run in busy polling mode\n"
		"    -B    number of packets to submit at the same time\n"
		"    -c    run in copy mode\n"
		"    -C    do _not_ request checksum offload\n",
		"    -d    debug mode: single packet, sleep between them\n"
		"    -q    rx-tx queue number\n",
		"    -r    don't install dummy xdp (rx) program\n",
		"    -R    number of entries in fill/comp/rx/tx rings (per ring)\n",
		"    -m    request tx offloads\n",
		"    -M    fill tx offloads but don't set XDP_TX_METADATA\n",
		"    -l    stop after sending given number of packets\n",
		"    -s    packet payload size (1400 is default)\n",
		"    -T    do _not_ request tx timestamp\n",
		"    -U    number of entries in umem\n",
		prog);
}

int main(int argc, char *argv[])
{
	int bind_flags =  XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
	bool install_rx = true;
	long long limit = -1;
	struct xsk xsk;
	int ifindex;
	int opt;
	int ret;
	int i;

	int qid = 0;

	struct bpf_program *prog;

	while ((opt = getopt(argc, argv, "bB:cCdq:rR:l:mMs:TU:")) != -1) {
		switch (opt) {
		case 'b':
			busy_poll = true;
			break;
		case 'B':
			batch_size = atoi(optarg);
			assert(batch_size > 0 & umem_size % 8 == 0);
			break;
		case 'c':
			bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;
			break;
		case 'C':
			fill_csum = false;
			break;
		case 'd':
			debug = true;
			batch_size = 1;
			break;
		case 'q':
			qid = atoi(optarg);
			break;
		case 'r':
			install_rx = false;
			break;
		case 'R':
			ring_size = atoi(optarg);
			assert(ring_size > 0 & ring_size % 8 == 0);
			break;
		case 'm':
			request_meta = true;
			fill_meta = true;
			break;
		case 'M':
			fill_meta = true;
			break;
		case 'l':
			limit = atoll(optarg);
			break;
		case 's':
			pkt_size = atoll(optarg);
			assert(pkt_size < 4096 - 256);
			break;
		case 'T':
			fill_tstamp = false;
			break;
		case 'U':
			umem_size = atoi(optarg);
			assert(umem_size > 0 & umem_size % 8 == 0);
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}
	assert(batch_size < umem_size);

	if (argc < 1 + 7 || optind >= argc) {
		usage(basename(argv[0]));
		return -1;
	}

	ifname = argv[optind];
	ifindex = if_nametoindex(ifname);

	sscanf(argv[optind + 1], "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
	       &smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
	sscanf(argv[optind + 2], "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
	       &dmac[0], &dmac[1], &dmac[2], &dmac[3], &dmac[4], &dmac[5]);

	inet_pton(AF_INET6, argv[optind + 3], &saddr);
	inet_pton(AF_INET6, argv[optind + 4], &daddr);

	sport = atoi(argv[optind + 5]);
	dport = atoi(argv[optind + 6]);

	printf("open_xsk:");
	printf(" ifname=%s", ifname);
	printf(" ifindex=%d", ifindex);
	printf(" qid=%d", qid);
	printf(" bind_flags=%x", bind_flags);
	printf(" fill_meta=%d", fill_meta);
	printf(" fill_csum=%d", fill_csum);
	printf(" fill_tstamp=%d", fill_tstamp);
	printf(" request_meta=%d", request_meta);
	printf(" ring_size=%d", ring_size);
	printf(" umem_size=%d", umem_size);
	printf("\n");

	ret = open_xsk(ifindex, &xsk, qid, bind_flags);
	if (ret)
		error(1, -ret, "open_xsk");

	if (install_rx) {
		printf("install dummy xdp program\n");
		ret = dummy_rx(ifindex);
		if (ret)
			error(1, -ret, "dummy_rx");
	}

	printf("xsk->fd=%d\n", xsk.fd);

	printf("populate_umem\n");
	populate_umem(&xsk);

	printf("generate_tx, press any key to exit...\n");
	generate_tx(&xsk, limit);

	close_xsk(&xsk);
}
