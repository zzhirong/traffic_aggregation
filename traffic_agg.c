//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h> // For TC_ACT_OK
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // For bpf_ntohs

// Define a hash map called 'ip_stats'
// Key: u32 source IP address (IPv4)
// Value: u64 byte count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Adjust size as needed
    __type(key, __u32);         // Source IPv4 address
    __type(value, __u64);       // Byte count
} ip_stats SEC(".maps");

SEC("tc") // Section for Traffic Control classifier
int tc_aggregate(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    // Check packet boundaries for Ethernet header
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK; // Not enough data for Ethernet header
    }

    // We only care about IPv4 packets for this example
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK; // Not an IPv4 packet
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Check packet boundaries for IP header
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK; // Not enough data for IP header
    }

    // Get source IP address (already in network byte order)
    __u32 src_ip = ip->saddr;
    // Get packet length (use skb->len for total captured length)
    __u64 packet_len = skb->len;

    // Lookup the current count for this source IP
    __u64 *current_count = bpf_map_lookup_elem(&ip_stats, &src_ip);
    __u64 new_count;

    if (current_count) {
        // Found existing entry, increment count atomically (important!)
        // Using __sync_fetch_and_add or bpf_atomic_add would be better if available
        // and needed for high contention, but simple update is often okay for stats.
         new_count = *current_count + packet_len;
        // For high packet rates, consider using PERCPU maps to avoid lock contention.
    } else {
        // No entry found, initialize count
        new_count = packet_len;
    }

    // Update the map with the new count
    // The flags=BPF_ANY means insert if not present, update if present.
    bpf_map_update_elem(&ip_stats, &src_ip, &new_count, BPF_ANY);

    // Let the packet continue through the network stack
    return TC_ACT_OK;
}

// Required license for the kernel module
char __license[] SEC("license") = "GPL";
