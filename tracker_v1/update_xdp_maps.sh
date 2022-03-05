#!/bin/bash

#map create - dns query - done in <*_user>.c
#bpftool map create /sys/fs/bpf/query flags 1 \
#	name query type hash key 4 value 262 entries 100

#map create  - allowed domains - done in <*_user>.c
#bpftool map create /sys/fs/bpf/allowed_domains flags 1 \
#	name allowed_domains type hash key 4 value 8 entries 3

#associate the pinned map with the maps in the XDP program - done in <*_user>.c
#bpftool prog load xdp_extract_query.o /sys/fs/bpf/xdp_extract_query type xdp \
#	map name query pinned /sys/fs/bpf/query 

#associate XDP program with wanted device (eth0) - done in <*_user>.c
#ip --force link set dev $DEV xdpgeneric \
#	pinned /sys/fs/bpf/xdp_extract_query

#add "com" "net" "org" domains to the map
# com
bpftool map update pinned /sys/fs/bpf/allowed_domains \
	key 0x63 0x6f 0x6d 0x00 \
	value 00 00 00 00

# net
#bpftool map update pinned /sys/fs/bpf/allowed_domains \
#	key 0x6e 0x65 0x74 0x00 \
#	value 00 00 00 00

# org
bpftool map update pinned /sys/fs/bpf/allowed_domains \
	key 0x6f 0x72 0x67 0x00 \
	value 00 00 00 00

bpftool map update pinned /sys/fs/bpf/packets_counters \
	key 00 00 00 00 \
	value 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 


