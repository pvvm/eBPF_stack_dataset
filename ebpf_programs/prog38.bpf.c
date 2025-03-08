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


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
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

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
	void *data_end,
	struct ipv6hdr **ip6hdr)
{
struct ipv6hdr *ip6h = nh->pos;

if (ip6h + 1 > data_end)
return -1;

nh->pos = ip6h + 1;
*ip6hdr = ip6h;

return ip6h->nexthdr;
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

	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;

	nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
	if (nh_type != IPPROTO_ICMPV6)
		return XDP_DROP;


    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";