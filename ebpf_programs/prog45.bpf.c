/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_NUMBER_CORES 8

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_NUMBER_CORES);
} common_array SEC(".maps");

struct info {
    __u64 latency;
    __u64 counter;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct info);
    __uint(max_entries, MAX_NUMBER_CORES);
} info_array SEC(".maps");

static __always_inline int update_info (__u64 arrival_time, __u64 finish_time, int key_cpu) {
    struct info *value = bpf_map_lookup_elem(&info_array, &key_cpu);
    if(!value)
        return 0;

    struct info new_value;
    new_value.latency = value->latency + (finish_time - arrival_time);
    new_value.counter = value->counter + 1;
    bpf_map_update_elem(&info_array, &key_cpu, &new_value, BPF_ANY);

    return 1;
}


static __always_inline int lookup_map (int key, void * map_pointer) {
    __u64 * value = bpf_map_lookup_elem(map_pointer, &key);

    if(!value)
        return 0;

    *value += 1;

    return 1;
}


SEC("xdp")
int  xdp_prog(struct xdp_md *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();

    __u64 arrival_time = bpf_ktime_get_ns();

    lookup_map(cpu, &common_array);

    __u64 finish_time = bpf_ktime_get_ns();
    if(!update_info(arrival_time, finish_time, cpu)) {
        bpf_printk("Error while looking up timer map");
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";