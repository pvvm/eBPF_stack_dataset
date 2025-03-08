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

struct map_locked_value {
    __u64 value;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct map_locked_value);
    __uint(max_entries, MAX_NUMBER_CORES);
} lock_array SEC(".maps");

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


static __always_inline int lookup_lock_map (int key) {

    struct map_locked_value *lock_value = bpf_map_lookup_elem(&lock_array, &key);

    if(!lock_value) {
        return 0;
    }

    bpf_spin_lock(&lock_value->lock);

    lock_value->value += 1;
    bpf_spin_unlock(&lock_value->lock);

    return 1;
}

SEC("xdp")
int  lock_map(struct xdp_md *ctx)
{
    int cpu = bpf_get_smp_processor_id();

    __u64 arrival_time = bpf_ktime_get_ns();

    lookup_lock_map(0);

    __u64 finish_time = bpf_ktime_get_ns();
    if(!update_info(arrival_time, finish_time, cpu)) {
        return XDP_DROP;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";