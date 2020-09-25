/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>		// struct ethhdr
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> 		// bpf_ntohs
#include <iproute2/bpf_elf.h>
#include <linux/time.h>
//#include <netinet/in.h>
#include <linux/ip.h>
#include "defines.h"			// Definition of common parameters
#include "parsing.h"

#ifdef _DEBUG_
#define bpf_debug(fmt, ...)                          \
    ({                                               \
        char ____fmt[] = fmt;                        \
        bpf_trace_printk(____fmt, sizeof(____fmt),   \
            ##__VA_ARGS__);                          \
    })
#else
#define bpf_debug(fmt, ...)                          \
{}
#endif

/* TODO: Improve performance by using multiple per-cpu hash maps.
 */
struct bpf_map_def SEC("maps") fl_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = NBINS,
	.map_flags = BPF_ANY
};

static unsigned int print_map()
#ifdef _DEBUG_
{
	/*__u32 key = 0;
	__u32 *counter = 0;
	__u32 value = 0;
	
	for(unsigned int i=0;i<NBINS;i++)
	{
		counter = bpf_map_lookup_elem(&fl_stats, &key);
		if(counter)
			value=*counter;
		else
			value=0;
		bpf_debug("[%d]: %d\n", key, value);
		key += 1;
	} */
	return 0;
};
#else
{
	return 0;
};
#endif

			
SEC("tc_flowlabel_stats")
int  flow_label_stats(struct __sk_buff *skb)
{
	/* Preliminary step: cast to void*.
	 * (Not clear why data/data_end are stored as long)
	 */
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	__u32 flowlabel = 0;
	__u32 len = 0;
	__u32 init_value = 1;
	int eth_proto, ip_proto = 0;
	/* int eth_proto, ip_proto, icmp_type = 0; */
/*	struct flowid flow = { 0 }; */
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct ipv6hdr* iph6;
	__u64 ts, te;

	ts = bpf_ktime_get_ns();	
	
	/* Parse Ethernet header and verify protocol number. */
	nh.pos = data;
	len = data_end - data;
	eth = (struct ethhdr *)data;
	eth_proto = parse_ethhdr(&nh, data_end, &eth);
	if ( eth_proto < 0 ) {
		bpf_debug("Unknown ethernet protocol/Too many nested VLANs.\n");
		return TC_ACT_OK; /* TODO: XDP_ABORT? */
	}
	if ( eth_proto != bpf_htons(ETH_P_IPV6) )
	{
		return TC_ACT_OK;
	}

	/* Parse IP header and verify protocol number. */
	if( (ip_proto = parse_ip6hdr(&nh, data_end, &iph6)) < 0 ) {
		return TC_ACT_OK;
	}	

	/* Check flow label
	 */
	if( (void*) iph6 + sizeof(struct ipv6hdr) < data_end) {
		for(short i=0;i<3;i++) {
			flowlabel |= iph6->flow_lbl[i];
			if(i==0) {
				/* Remove DSCP value */
				flowlabel &=0x0f;
			}
			if(i!=2)
				flowlabel <<= 8;
		}
	}

	/* Collect the required statistics. */

	/* Update the values in the histogram.
	 * How the historgram map works. There are BINS=2^BINBASE bins, equally sized. The full
	 * space of flow label values is 2^20 wide. So, the size of each bin is 
	 * 2^20/BINS = 2^20/2^BINBASE =  2^(20-BINBASE)
	 * This means the first (20-BINBASE) bits are the bin selector (for instance, 0x0 means all
	 * flow labels from 0x0 to 2^(20-BINBASE)-1. To find the selector, is is enough to shift
	 * the flow label right of (20-BINBASE) bits.
	 */
	__u32 key = flowlabel >> (20-BINBASE);
	__u32 *counter = bpf_map_lookup_elem(&fl_stats, &key);
	if(!counter)
		bpf_map_update_elem(&fl_stats, &key, &init_value, BPF_ANY);
	else
		__sync_fetch_and_add(counter, 1);

	print_map();
	  

	te = bpf_ktime_get_ns();
	bpf_debug("Time elapsed: %d", te-ts);
	
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
