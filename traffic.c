//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // IPv4 地址
    __type(value, __u64);    // 字节计数
} ip_stats SEC(".maps");

SEC("xdp")
int traffic_monitor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 ip;
    __u64 *bytes;
    __u64 new_bytes = 0;

    // 使用IP头部的total_length字段获取完整的IP包大小
    __u64 packet_size = (__u64)bpf_ntohs(iph->tot_len);

    // 统计源IP的流量
    ip = iph->saddr;
    bytes = bpf_map_lookup_elem(&ip_stats, &ip);
    if (bytes) {
	new_bytes = *bytes + packet_size;
    } else {
        new_bytes = packet_size;
    }
    bpf_map_update_elem(&ip_stats, &ip, &new_bytes, BPF_ANY);

    // 统计目标IP的流量
    ip = iph->daddr;
    bytes = bpf_map_lookup_elem(&ip_stats, &ip);
    if (bytes) {
	new_bytes = *bytes + packet_size;
    } else {
        new_bytes = packet_size;
    }
    bpf_map_update_elem(&ip_stats, &ip, &new_bytes, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
