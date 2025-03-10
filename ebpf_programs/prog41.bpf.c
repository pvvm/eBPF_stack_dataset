// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct hdr_cursor {
	void *pos;
};


int parse_ethhdr(struct hdr_cursor *nh,
    void *data_end,
    struct ethhdr **ethhdr)
{
struct ethhdr *eth = nh->pos;
int hdrsize = sizeof(*eth);

if (nh->pos + 1 > data_end)
return -1;

nh->pos += hdrsize;
*ethhdr = eth;

return eth->h_proto;
}


int parse_iphdr(struct hdr_cursor *nh,
	void *data_end,
	struct iphdr **iphdr)
{
struct iphdr *iph = nh->pos;
int hdrsize;

if (iph + 1 > data_end)
return -1;

hdrsize = iph->ihl * 4;

if(hdrsize < sizeof(*iph))
return -1;

if (nh->pos + hdrsize > data_end)
return -1;

nh->pos += hdrsize;
*iphdr = iph;

return iph->protocol;
}

int parse_icmphdr(struct hdr_cursor *nh,
	void *data_end,
	struct icmphdr **icmphdr)
{
struct icmphdr *icmph = nh->pos;

if (icmph + 1 > data_end)
return -1;

nh->pos  = icmph + 1;
*icmphdr = icmph;

return icmph->type;
}


SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	struct hdr_cursor nh;
	int nh_type;

	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6))
        return XDP_DROP;

		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != 0)
			return XDP_DROP;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			return XDP_DROP;

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";