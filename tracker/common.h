#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h> //for uint<size>_t

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
//#include "../libbpf/src/libbpf.h"
#include "../libbpf/src/bpf_helpers.h"
#include "../libbpf/src/bpf_endian.h"

//Defines
#define MAX_QUERY_LENGTH 50
#define MAX_ALLOWED_QUERY_LENGTH 30
#define BLOCK_TIME 5000000000 //5 secs

struct dns_query{
	uint16_t qtype;
	uint16_t qclass;
	uint16_t qlength;
	char qname[MAX_QUERY_LENGTH];		
};

//extracted from internet - known header
struct dns_hdr{
	uint16_t id;

	uint8_t rd	:1;//recursion desired
	uint8_t tc	:1;//truncated message
	uint8_t aa	:1;//authoritive answer
	uint8_t opcode	:4;//purpose of message
	uint8_t qr	:1;//query/response flag

	uint8_t rcode	:4;//response code
	uint8_t cd	:1;//checking desiabled
	uint8_t ad	:1;//authenticated data
	uint8_t z	:1;// reserved
	uint8_t ra	:1;//recursion available

	uint16_t qdcount;//number of question entries
	uint16_t ancount;//number of answer entries
	uint16_t nscount;//number of authority entries
	uint16_t arcount;//number of resource entries
};

//contains counts for XDP program analyze
struct counters{
	uint64_t dropped_packets_name;//dropped by name filter
	uint64_t dropped_packets_length;//dropped by length filter
	uint64_t passed_packets;	//passed
};

struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = 3
};

struct bpf_map_def SEC("maps") allowed_domains = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(uint32_t), 
	.value_size = sizeof(uint32_t), 
	.max_entries = 2,//TODO #define
	.map_flags = 1
};

struct bpf_map_def SEC("maps") query = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(uint32_t), //IP address
	.value_size = sizeof(struct dns_query), 
	.max_entries = 100,//TODO #define
	.map_flags = 1
};

struct bpf_map_def SEC("maps") packets_counters = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct counters),
	.max_entries = 1
};

struct bpf_map_def SEC("maps") hosts_rate = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(uint32_t), //IP addr
	.value_size = sizeof(uint64_t), //time in ns
	.max_entries = 1000	
};

#endif


