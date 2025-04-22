#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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
    __u64 new_bytes = 1;

    // 统计源IP的流量
    ip = iph->saddr;
    bytes = bpf_map_lookup_elem(&ip_stats, &ip);
    if (bytes) {
        new_bytes = *bytes + (data_end - data);
    }
    bpf_map_update_elem(&ip_stats, &ip, &new_bytes, BPF_ANY);

    // 统计目标IP的流量
    ip = iph->daddr;
    bytes = bpf_map_lookup_elem(&ip_stats, &ip);
    if (bytes) {
        new_bytes = *bytes + (data_end - data);
    }
    bpf_map_update_elem(&ip_stats, &ip, &new_bytes, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";