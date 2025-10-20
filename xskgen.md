# xskgen

Try to saturate single NIC TX queue. Optionally use TX offloads to populate
TX timestamp and TX checksum.

All UMEM chunks are pre-populated with the packet payload, so the cost
of the userspace side is minimal. L4 protocol is always UDP.

# Credits

The code is heavily based on the following files from Linux Kernel:

- tools/testing/selftests/bpf/xsk.{h,c} (Magnus Karlsson et all)
- tools/testing/selftests/bpf/xdp_hw_metadata.c (Stanislav Fomichev et all)