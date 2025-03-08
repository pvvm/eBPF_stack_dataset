// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct hdr_cursor {
	void *pos;
};


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
    void *data_end,
    struct ethhdr **ethhdr)
{
struct ethhdr *eth = nh->pos;
int hdrsize = sizeof(*eth);

/* Byte-count bounds check; check if current pointer + size of header
* is after data_end.
*/
if (nh->pos + 1 > data_end)
return -1;

nh->pos += hdrsize;
*ethhdr = eth;

return eth->h_proto; /* network-byte-order */
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6))
        return XDP_DROP;

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";