
#include <stdio.h>
#include <unistd.h>
#include <net/if.h> // for if_nametoindex
#include "bpf.h"
#include "libbpf.h"

#define DEFAULT_IFACE "enp0s3"

#define QUERY_MAP_PIN_PATH "/sys/fs/bpf/query"
#define ALLOWED_DOMAINS_MAP_PIN_PATH "/sys/fs/bpf/allowed_domains"
#define HOSTS_RATE_MAP_PIN_PATH "/sys/fs/bpf/hosts_rate"
#define PACKETS_COUNTERS_MAP_PIN_PATH "/sys/fs/bpf/packets_counters"

#define QUERY_TBL "query"
#define ALLOWED_DOMAINS_TBL "allowed_domains"
#define HOSTS_RATE_TBL "hosts_rate"
#define PACKETS_COUNTERS_TBL "packets_counters"

#define JMP_TBL "jmp_table"

struct domain_name{
	uint32_t length;
	char domain[4];
};
int main(int argc, char *argv[]){
	const char *ifname = DEFAULT_IFACE;
	const char *query_pin_path = QUERY_MAP_PIN_PATH;
	const char *allowed_domains_pin_path = ALLOWED_DOMAINS_MAP_PIN_PATH;
	const char *hosts_rate_pin_path = HOSTS_RATE_MAP_PIN_PATH;
	const char *packets_counters_pin_path = PACKETS_COUNTERS_MAP_PIN_PATH;
	const char *xdp_program_name = NULL;

	unsigned int ifindex = 0;
	struct bpf_program *prog = NULL;
	struct bpf_object *obj = NULL;
	struct bpf_map *query = NULL;
	struct bpf_map *allowed_domains = NULL;
	struct bpf_map *hosts_rate = NULL;
	struct bpf_map *packets_counters = NULL;
	int fd = -1, jmp_tbl_fd = -1, main_fd = -1;
	uint32_t key = 0;
	
	if(!(ifindex = if_nametoindex(ifname)))
		printf("Error: finding device %s\n failed", ifname);
	else if(!(obj = bpf_object__open_file("xdp_network_tracker.o", NULL))
		|| libbpf_get_error(obj))
		printf("Error: opening BPF object file failed\n");
	else if(!(query = bpf_object__find_map_by_name(obj, QUERY_TBL)))
		printf("Error: table " QUERY_TBL " not found\n");
	else if(bpf_map__set_pin_path(query, query_pin_path))
		printf("Error: pinning " QUERY_TBL " to \"%s\" failed\n", query_pin_path);
	else if(!(allowed_domains = bpf_object__find_map_by_name(obj, ALLOWED_DOMAINS_TBL)))
		printf("Error: table " ALLOWED_DOMAINS_TBL " not found\n");
	else if(bpf_map__set_pin_path(allowed_domains, allowed_domains_pin_path))
		printf("Error: pinning " ALLOWED_DOMAINS_TBL " to \"%s\" failed\n", allowed_domains_pin_path);
	else if(!(hosts_rate = bpf_object__find_map_by_name(obj, HOSTS_RATE_TBL)))
		printf("Error: table " ALLOWED_DOMAINS_TBL " not found\n");
	else if(bpf_map__set_pin_path(hosts_rate, hosts_rate_pin_path))
		printf("Error: pinning " HOSTS_RATE_TBL " to \"%s\" failed\n", hosts_rate_pin_path);
	else if(!(packets_counters = bpf_object__find_map_by_name(obj, PACKETS_COUNTERS_TBL)))
		printf("Error: table " PACKETS_COUNTERS_TBL " not found\n");
	else if(bpf_map__set_pin_path(packets_counters, packets_counters_pin_path))
		printf("Error: pinning " PACKETS_COUNTERS_TBL " to \"%s\" failed\n", hosts_rate_pin_path);
	else if(bpf_object__load(obj))
		printf("Error: loading BPF obj file failed\n");
	else if((jmp_tbl_fd = bpf_object__find_map_fd_by_name(obj, JMP_TBL)) < 0)
		printf("Error: table " JMP_TBL " not found\n");
	else bpf_object__for_each_program(prog, obj){
		xdp_program_name = bpf_program__section_name(prog);
		fd = bpf_program__fd(prog);
		if(!strcmp(xdp_program_name, "xdp-receive-packet"))
			main_fd = fd;
		printf(JMP_TBL " entry key -> name -> fd\n: %d -> %s -> %d\n", key, xdp_program_name, fd);
		if(bpf_map_update_elem(jmp_tbl_fd, &key, &fd, BPF_ANY)<0){
			printf("Error: making entry for %s\n", xdp_program_name);
			fd = -1;
			return -1;
		}
		++key;
	}
	if(fd < 0 || main_fd < 0)
		;
	if(bpf_set_link_xdp_fd(ifindex,main_fd,0))
		printf("Error: attaching xdp program to device\n");
	else{
		printf("main_fd:%d\n", main_fd);
		printf("Program attached and running.\nPress Ctrl-C to stop followed by make unload\n");
		while(true)
			sleep(60);
	}
	return -1;
}
