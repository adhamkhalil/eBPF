/* SPDX-License-Identifier: GPL-2.0 */
//char LICENSE[] SEC("license") = "GPL";

#include "common.h"

#define XDP_LEGAL_DOMAIN 1
#define XDP_HOST_RATE 2

//returns query (in dns_query) and query length
static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q);
//returns request domain in curr_domain
static int parse_host_domain(struct dns_query *q, char *curr_domain);
static uint32_t get_ip_addr(struct xdp_md *ctx);

SEC("xdp-receive-packet")
int  dns_extract_query(struct xdp_md *ctx){
	//packet is between data & data_end starting from ethernet
	void *data = (void *)(long)ctx->data; 
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	uint32_t saddr = 0;
	
	if((void *)eth + sizeof(*eth) > data_end){
		return XDP_DROP;
	}
	ip = data + sizeof(*eth);
	if((void *)ip + sizeof(*ip) > data_end){
		return XDP_DROP;
	}
	if(ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udp = (void *)ip + sizeof(*ip);
	if((void *)udp + sizeof(*udp) > data_end){
		return XDP_DROP;
	}
	if(udp->dest != __bpf_htons(53) ){
		return XDP_PASS;
	}
	if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end)
		return XDP_DROP;
	struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	if(dns_hdr->qr == 0){
		saddr = ip->saddr;
		void *dns_start = (void *)dns_hdr + sizeof(struct dns_hdr); 
		struct dns_query q;
		int q_length;
		q_length = parse_query(ctx, dns_start, &q);
		//check if query has allowed domain name
		if(q_length != -1){
			bpf_map_update_elem(&query, &saddr, &q, BPF_ANY);
			//call tail function
			bpf_tail_call(ctx, &jmp_table, XDP_LEGAL_DOMAIN);
			return XDP_PASS;
		}else{
			return XDP_DROP;
		}
	}
	return XDP_PASS;
}



SEC("xdp-check-if-legal-domain")
int  dns_legal_domain(struct xdp_md *ctx){
	uint32_t saddr = -1, to_drop = 0, key = 0;
	if((saddr = get_ip_addr(ctx)) == -1)
		return XDP_DROP;
	struct counters *pkts_counters = bpf_map_lookup_elem(&packets_counters,&key);
	if(!pkts_counters) return XDP_DROP;
	struct dns_query *q = NULL;
	//get host query
       	if(!(q = bpf_map_lookup_elem(&query, &saddr)))
		return XDP_DROP;
	char curr_domain[MAX_QUERY_LENGTH];
	__builtin_memset(curr_domain, 0, sizeof(curr_domain));
	//get domain from query
	if(parse_host_domain(q, curr_domain))
		return XDP_DROP;
	//check if it's an allowed domain
	struct counters bad_update;
	bad_update.dropped_packets_name = pkts_counters->dropped_packets_name;
	bad_update.dropped_packets_length = pkts_counters->dropped_packets_length;
	bad_update.passed_packets = pkts_counters->passed_packets;
	uint32_t *is_allowed = NULL;
	if(!(is_allowed=bpf_map_lookup_elem(&allowed_domains, curr_domain))){
		bad_update.dropped_packets_name = pkts_counters->dropped_packets_name + 1;
		to_drop = 1;
	}else if(q->qlength>=MAX_ALLOWED_QUERY_LENGTH){
		bad_update.dropped_packets_length = pkts_counters->dropped_packets_length + 1;
		to_drop = 1;
	}
	if(to_drop == 1){
		bpf_map_update_elem(&packets_counters, &key, &bad_update, BPF_ANY);
		uint64_t first_query_time = bpf_ktime_get_ns();
		bpf_map_update_elem(&hosts_rate, &saddr, &first_query_time, BPF_ANY);
	}
	bpf_tail_call(ctx, &jmp_table, XDP_HOST_RATE);
	return XDP_DROP;
}

SEC("xdp-check-host-rate")
int  check_host_rate(struct xdp_md *ctx){
	uint32_t saddr = -1, key = 0;
	struct counters *pkts_counters = bpf_map_lookup_elem(&packets_counters,&key);
	if(!pkts_counters) return XDP_DROP;
	if((saddr = get_ip_addr(ctx)) == -1)
		return XDP_DROP;
	struct dns_query *q = bpf_map_lookup_elem(&query, &saddr);
	if(!q) return XDP_DROP;

	uint64_t *exists_time = NULL, curr_time=0;
	if((exists_time = bpf_map_lookup_elem(&hosts_rate, &saddr))){
		curr_time = bpf_ktime_get_ns();
		if(curr_time - *exists_time < BLOCK_TIME){
			return XDP_DROP;	
		}else{
			bpf_map_delete_elem(&hosts_rate, &saddr);
			return XDP_PASS;
		}
	}
	//Reaching here means packet should be PASSED;
	struct counters good_update;
	good_update.dropped_packets_length = pkts_counters->dropped_packets_length;
	good_update.dropped_packets_name = pkts_counters->dropped_packets_name;
	good_update.passed_packets = pkts_counters->passed_packets + 1;
	bpf_map_update_elem(&packets_counters, &key, &good_update, BPF_ANY);

	return XDP_PASS;
}

static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q){
	void *data_end = (void *)(long)ctx->data_end;
	void *cursor = query_start;
	uint16_t pos = 0, i=0;
	__builtin_memset(&q->qname[0], 0, sizeof(q->qname));
	q->qclass = 0; q->qtype = 0;
	for(i=0; i<MAX_QUERY_LENGTH; ++i){
		if(cursor + 1 > data_end)
			break;
		if(*(char *)(cursor) == 0){
			if(cursor + 5 > data_end)//can't get record and type
				break;
			else{
				q->qtype = bpf_htons(*(uint16_t *)(cursor+1));
				q->qclass = bpf_htons(*(uint16_t *)(cursor+3));
				q->qlength = pos;
			}
			q->qname[pos] = *(char *)(cursor);
			return pos + 1 + 2 + 2;
		}
		q->qname[pos] = *(char *)(cursor);
		++pos;
		++cursor;
	}
	return -1;
}

static int parse_host_domain(struct dns_query *q, char *curr_domain){
	uint32_t k=0;
	for(int i=0; i<MAX_QUERY_LENGTH; ++i){
		if(q->qname[i] == '\x03'){// \0x3 is ETX - end of text
			__builtin_memset(curr_domain, 0, MAX_QUERY_LENGTH);
			k=0;
			continue;
		}	
		else if(q->qname[i] == '\0'){
			break;
		}
		curr_domain[k++] = q->qname[i];
	}
	return 0;
}

static uint32_t get_ip_addr(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data; 
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	
	if((void *)eth + sizeof(*eth) > data_end){
		return -1;
	}
	ip = data + sizeof(*eth);
	if((void *)ip + sizeof(*ip) > data_end){
		return XDP_DROP;
	}
	if(ip->protocol != IPPROTO_UDP)
		return -1;
	return ip->saddr;

}

