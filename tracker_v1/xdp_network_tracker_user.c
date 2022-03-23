
/* 1) Includes */
#include <stdio.h>
#include <unistd.h>
#include <net/if.h> // for if_nametoindex
#include <time.h>
#include "bpf.h"
#include "libbpf.h"

/* 2) Defines */
#define BLOCK_TIME 5000000000 
#define DEFAULT_IFACE "ens33"
#define QUERY_MAP_PIN_PATH "/sys/fs/bpf/query"
#define ALLOWED_DOMAINS_MAP_PIN_PATH "/sys/fs/bpf/allowed_domains"
#define HOSTS_RATE_MAP_PIN_PATH "/sys/fs/bpf/hosts_rate"
#define PACKETS_COUNTERS_MAP_PIN_PATH "/sys/fs/bpf/packets_counters"
#define QUERY_TBL "query"
#define ALLOWED_DOMAINS_TBL "allowed_domains"
#define HOSTS_RATE_TBL "hosts_rate"
#define PACKETS_COUNTERS_TBL "packets_counters"
#define JMP_TBL "jmp_table"


/* 3) Implementation */
int main(int argc, char *argv[])
{
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
	int fd = -1, jmp_tbl_fd = -1, main_fd = -1,hosts_rate_map_fd = -1, deleted_map_entries = 0;
	uint32_t key = 0, next_key=0;
	uint64_t value = 0;
	struct timespec ts;

	/* 1) Get ETH interface index */
	if(!(ifindex = if_nametoindex(ifname)))
	{
		printf("Error: finding device %s\n failed", ifname);
		return -1;
	}


	/* 2) Verify XDP object file existence */
	if(!(obj = bpf_object__open_file("xdp_network_tracker.o", NULL)) || libbpf_get_error(obj))
	{
		printf("Error: opening BPF object file failed\n");
		return -1;
	}

	/* 3) Pin Maps*/
	/* 3.1) Query Map */
	if(!(query = bpf_object__find_map_by_name(obj, QUERY_TBL)))
	{
		printf("Error: table " QUERY_TBL " not found\n");
		return -1;
	}

	/* 3.1.1) Pin Map */
	if(bpf_map__set_pin_path(query, query_pin_path))
	{
		printf("Error: pinning " QUERY_TBL " to \"%s\" failed\n", query_pin_path);
		return -1;
	}
	
	/* 3.2) Allowed Domains Map */
	if(!(allowed_domains = bpf_object__find_map_by_name(obj, ALLOWED_DOMAINS_TBL)))
	{
		printf("Error: table " ALLOWED_DOMAINS_TBL " not found\n");
		return -1;
	}

	/* 3.2.1) Pin Map */
	if(bpf_map__set_pin_path(allowed_domains, allowed_domains_pin_path)){
		printf("Error: pinning " ALLOWED_DOMAINS_TBL " to \"%s\" failed\n", allowed_domains_pin_path);
		return -1;
	}

	/* 3.3) Hosts rate Map */
	if(!(hosts_rate = bpf_object__find_map_by_name(obj, HOSTS_RATE_TBL)))
	{
		printf("Error: table " ALLOWED_DOMAINS_TBL " not found\n");
		return -1;
	}

	/* 3.3.1) Pin Map */
	if(bpf_map__set_pin_path(hosts_rate, hosts_rate_pin_path))
	{
		printf("Error: pinning " HOSTS_RATE_TBL " to \"%s\" failed\n", hosts_rate_pin_path);
		return -1;
	}

	/* 3.4) Packets Counters Map*/
	if(!(packets_counters = bpf_object__find_map_by_name(obj, PACKETS_COUNTERS_TBL)))
	{
		printf("Error: table " PACKETS_COUNTERS_TBL " not found\n");
		return -1;
	}

	/* 3.4.1) Pin Map */
	if(bpf_map__set_pin_path(packets_counters, packets_counters_pin_path))
	{
		printf("Error: pinning " PACKETS_COUNTERS_TBL " to \"%s\" failed\n", hosts_rate_pin_path);
		return -1;
	}

	/* 4) Load XDP object file */
	if(bpf_object__load(obj))
	{
		printf("Error: loading BPF obj file failed\n");
		return -1;
	}

	/* 5) Find XDP progs map file descriptor */		
	if((jmp_tbl_fd = bpf_object__find_map_fd_by_name(obj, JMP_TBL)) < 0)
	{
		printf("Error: table " JMP_TBL " not found\n");
		return -1;
	}

	/* 6) Fill XDP Programs Map by Iterating XDP Sections*/
	bpf_object__for_each_program(prog, obj)
	{
		xdp_program_name = bpf_program__section_name(prog);
		fd = bpf_program__fd(prog);
		if(!strcmp(xdp_program_name, "xdp-receive-packet"))
		{
			main_fd = fd;
		}
		printf(JMP_TBL " entry key -> name -> fd\n: %d -> %s -> %d\n", key, xdp_program_name, fd);
		if(bpf_map_update_elem(jmp_tbl_fd, &key, &fd, BPF_ANY)<0)
		{
			printf("Error: making entry for %s\n", xdp_program_name);
			fd = -1;
			return -1;
		}
		++key;
	}

	/* 6.4) Verify main program found */
	if(fd < 0 || main_fd < 0)
	{
		printf("Error: didn't find main program\n" );
		return -1;
	}
	
	/* 7) Link Main XDP Prog to ETH Interface*/
	if(bpf_set_link_xdp_fd(ifindex,main_fd,0))
	{
		printf("Error: attaching xdp program to device\n");
		return -1;
	}
	if((hosts_rate_map_fd = bpf_object__find_map_fd_by_name(obj, HOSTS_RATE_TBL)) < 0){
		printf("Error: table " HOSTS_RATE_TBL " not found\n");
		return -1;
	}

	/* 8) Loading Process Succeeded */	
	printf("Program attached and running.\nPress Ctrl-C to stop followed by make unload\n");
	while(true){
		sleep(60);
		deleted_map_entries = 0;
		key = -1;
		printf("Checking hosts_rate_map\n");
		while(bpf_map_get_next_key(hosts_rate_map_fd, &key, &next_key) == 0){
			//printf("Got key %d next: %d \n", key, next_key);
			int res = bpf_map_lookup_elem(hosts_rate_map_fd, &key, &value);
			if(res < 0){//first iteration key will be -1
				key = next_key;
				continue;
			}
			clock_gettime(CLOCK_MONOTONIC, &ts);
			if(ts.tv_nsec - value > BLOCK_TIME){
				deleted_map_entries++;
				uint32_t to_delete = key;
				key = next_key;
				bpf_map_delete_elem(hosts_rate_map_fd, &to_delete);
			}
		}
		//delete last element considered a special case, since upon last key
		//bpf_map_get_next_key returns -1
		int res = bpf_map_lookup_elem(hosts_rate_map_fd, &key, &value);
		if(res < 0){
			key = next_key;
			continue;
		}
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if(ts.tv_nsec - value > BLOCK_TIME){
			deleted_map_entries++;
			uint32_t to_delete = key;
			key = next_key;
			bpf_map_delete_elem(hosts_rate_map_fd, &to_delete);
		}
		printf("Deleted: %d entries from hosts_rate_map\n", deleted_map_entries);
	}
	return -1;
}
