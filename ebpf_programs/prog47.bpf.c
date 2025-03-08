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

struct inner_map_queue {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, __u64);
    __uint(max_entries, 32);
} inner_map_queue0 SEC(".maps"), inner_map_queue1 SEC(".maps"), inner_map_queue2 SEC(".maps"), inner_map_queue3 SEC(".maps"),
inner_map_queue4 SEC(".maps"), inner_map_queue5 SEC(".maps"), inner_map_queue6 SEC(".maps"), inner_map_queue7 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_NUMBER_CORES);
    __type(key, __u32);
    __array(values, struct inner_map_queue);
} outer_map_queue SEC(".maps") = {
    .values = {&inner_map_queue0, &inner_map_queue1, &inner_map_queue2, &inner_map_queue3,
    &inner_map_queue4, &inner_map_queue5, &inner_map_queue6, &inner_map_queue7}
};

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


__u64 lookup_map_of_maps_queue (int key, __u64 counter/*, int iteration*/) {

    struct inner_map_queue *map = bpf_map_lookup_elem(&outer_map_queue, &key);

    if(!map) {
        return 0;
    }

    __u64 value;

    if(bpf_map_peek_elem(map, &value) < 0) {
        return 0;
    }

    if(bpf_map_push_elem(map, &counter, BPF_EXIST) < 0) {
        return 0;
    }

    return counter;
}

__u64 get_counter (int key_cpu) {
    struct info *value = bpf_map_lookup_elem(&info_array, &key_cpu);
    if(!value)
        return 0;
    return value->counter;
}

SEC("xdp")
int  map_of_maps_queue(struct xdp_md *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();

    __u64 counter = get_counter(cpu);

    __u64 arrival_time = bpf_ktime_get_ns();

    lookup_map_of_maps_queue(cpu, counter);

    __u64 finish_time = bpf_ktime_get_ns();
    if(!update_info(arrival_time, finish_time, cpu)) {
        return XDP_DROP;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";