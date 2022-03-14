
#include "common.h"

#define XDP_LEGAL_DOMAIN 1
#define XDP_HOST_RATE 2
#define XDP_LOAD_BALANCER 3
#define bpf_printk2(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})
//returns query (in dns_query) and query length
static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q);
//returns request domain in curr_domain
static int parse_host_domain(struct dns_query *q, char *curr_domain);
//extracts ip address from packet IP header
static uint32_t get_ip_addr(struct xdp_md *ctx);
//check sum for ip header
static unsigned short checksum(unsigned short *ip, int iphdr_size);

static uint32_t forwarding_server = 0;
static uint32_t fwd_port = INITIAL_FWD_PORT;
static struct forwarding_server fwd_servers[NUM_OF_SERVERS] = {
	{.ip_addr = 134743044,
	 .mac = {0x00, 0x50, 0x56, 0xfb, 0x58, 0x8a}
	},
	{.ip_addr = 134744072,
	 .mac = {0x00, 0x50, 0x56, 0xfb, 0x58, 0x8a}
	},
}; 

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
			bpf_printk2("domain: %s", q.qname);
			//call tail function
			bpf_tail_call(ctx, &jmp_table, XDP_LEGAL_DOMAIN);
		}
		return XDP_DROP;
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
	uint32_t *is_allowed = NULL;
	if(!(is_allowed=bpf_map_lookup_elem(&allowed_domains, curr_domain))){
		pkts_counters->dropped_packets_name = pkts_counters->dropped_packets_name + 1;
		to_drop = 1;
	}else if(q->qlength>=MAX_ALLOWED_QUERY_LENGTH){
		pkts_counters->dropped_packets_length = pkts_counters->dropped_packets_length + 1;
		to_drop = 1;
	}
	if(to_drop == 1){
		bpf_map_update_elem(&packets_counters, &key, pkts_counters, BPF_ANY);
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
			//return XDP_PASS;
		}
	}
	//Reaching here means packet should be PASSED;
	pkts_counters->dropped_packets_length = pkts_counters->dropped_packets_length;
	pkts_counters->dropped_packets_name = pkts_counters->dropped_packets_name;
	pkts_counters->passed_packets = pkts_counters->passed_packets + 1;
	bpf_map_update_elem(&packets_counters, &key, pkts_counters, BPF_ANY);
	bpf_tail_call(ctx, &jmp_table, XDP_LOAD_BALANCER);
	return XDP_DROP;
}

SEC("xdp-load-balancer")
int load_balancer(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data; 
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	uint32_t addr = 0;
	
	if((void *)eth + sizeof(*eth) > data_end){
		return XDP_DROP;
	}
	ip = data + sizeof(*eth);
	if((void *)ip + sizeof(*ip) > data_end){
		return XDP_DROP;
	}
	if(ip->protocol != IPPROTO_UDP)
		return XDP_DROP;

	udp = (void *)ip + sizeof(*ip);
	if((void *)udp + sizeof(*udp) > data_end){
		return XDP_DROP;
	}
	if(udp->dest != __bpf_htons(53) ){
		return XDP_DROP;
	}

	if(forwarding_server >= NUM_OF_SERVERS) return XDP_DROP;

	if(forwarding_server == NUM_OF_SERVERS - 1){
		//We'll forward to 8.8.8.8 - 134744072 MAC: 00:50:56:fb:58:8a
		//Change MAC
		char *mac = fwd_servers[forwarding_server].mac;
		eth->h_dest[0] = mac[0];
		eth->h_dest[1] = mac[1];
		eth->h_dest[2] = mac[2] ;
		eth->h_dest[3] = mac[3] ;
		eth->h_dest[4] = mac[4];
		eth->h_dest[5] = mac[5];
		
		//Changes in ip header
		addr = bpf_ntohs(*(unsigned short *)&ip->daddr);
		ip->daddr = bpf_htonl(fwd_servers[1].ip_addr);
		ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
		
		//Changes in udp header; checksum = 0 => ignoring checking
		udp->source = bpf_ntohs(fwd_port);
		udp->check = 0;
		forwarding_server = 0;
		fwd_port = INITIAL_FWD_PORT;
	}else{
		//We'll forward to 8.8.4.4 - 134743044 MAC: 00:50:56:fb:58:8a
		char *mac = fwd_servers[forwarding_server].mac;
		eth->h_dest[0] = mac[0];
		eth->h_dest[1] = mac[1];
		eth->h_dest[2] = mac[2] ;
		eth->h_dest[3] = mac[3] ;
		eth->h_dest[4] = mac[4];
		eth->h_dest[5] = mac[5];

		//Changes in ip header		addr = bpf_ntohs(*(unsigned short *)&ip->daddr);
		ip->daddr = bpf_htonl(fwd_servers[0].ip_addr);
		ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
		
		//Changes in udp header; checksum = 0 => ignoring checking
		udp->source = bpf_ntohs(fwd_port);
		udp->check = 0;
		++forwarding_server;
		++fwd_port;
	}
	return XDP_TX;
}

static unsigned short checksum(unsigned short *ip, int iphdr_size){
	unsigned short s = 0;
	while(iphdr_size > 1){
		s += *ip;
		ip++;
		iphdr_size -= 2;
	}
	if(iphdr_size == 1)
		s += *(unsigned char *)ip;
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return ~s;
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
/* SPDX-License-Identifier: GPL-2.0 */
char LICENSE[] SEC("license") = "GPL";

