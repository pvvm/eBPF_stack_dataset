/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <time.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 100);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} array_map SEC(".maps");


struct test_struct {
    __u64 test0;
    __u8 test1;
    __u8 test2;
    __u8 test3;
    __u8 test4;
    __u8 test5;
    __u8 test6;
};

int test_function(__u32 var1) {
    struct test_struct var0 = {0,0,0,0,0,0,0};
    var0.test0 = var1;
    var0.test1 = var0.test0 * var1;
    var0.test2 = var0.test1 * var1;
    var0.test3 = var0.test2 * var1;
    var0.test4 = var0.test3 * var1;
    return var0.test4;
}

int test_function3(var2, var3) {
    return var2 + var3;
}

void test_function2() {
    __u8 var2 = 152;
    __u8 var3 = 143;
    __u16 var4 = 1;
    var2 = var3 + 123 + var2 + var4;
    const int key = 0;
    __u32 * teste = bpf_map_lookup_elem(&array_map, &key);
    const int key1 = 1;
    __u32 * teste1 = bpf_map_lookup_elem(&array_map, &key1);
    const int key2 = 2;
    __u32 * teste2 = bpf_map_lookup_elem(&array_map, &key2);
    const int key3 = 3;
    __u32 * teste3 = bpf_map_lookup_elem(&array_map, &key3);
    const int key4 = 4;
    __u32 * teste4 = bpf_map_lookup_elem(&array_map, &key4);
    const int key5 = 5;
    __u32 * teste5 = bpf_map_lookup_elem(&array_map, &key5);
    const int key6 = 6;
    __u32 * teste6 = bpf_map_lookup_elem(&array_map, &key6);
    if(!teste || !teste1 || !teste2 || !teste3 || !teste4 || !teste5 || !teste6)
        return;

    var4 = test_function3(var2, var3);

    int value = *teste;
    value = value + 53;
    return;
}

SEC("xdp")
int testing_stack(struct xdp_md *ctx)
{
    __u64 var1 = 123;

    var1 = test_function(var1);
    
    test_function2();

    return 0;
}

char _license[] SEC("license") = "GPL";
