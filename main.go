package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink" // Use netlink for TC setup
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf traffic_agg.c -- -I/usr/include -I/path/to/kernel/headers/include

// Define the structure expected by bpf2go based on the C code
// We don't strictly *need* this struct definition in Go *if* bpf2go works correctly,
// but it helps understand the map structure. The bpf2go generated code
// will provide the necessary types (like bpfIpStatsKey and bpfIpStatsValue).

const (
	// The qdisc handle for clsact attaches. Needs to be unique.
	qdiscParent = netlink.HANDLE_CLSACT
	// Hook point for TC BPF program (ingress)
	attachPoint = netlink.TC_H_INGRESS
)

func main() {
	ifaceName := flag.String("iface", "", "Network interface to attach to (e.g., eth0, wlan0)")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("-iface flag is required")
	}

	// --- Setup ---

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock limit:", err)
	}

	// Find the network interface by name.
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", *ifaceName, err)
	}

	// --- Load eBPF ---

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		// Extract loading errors for more details
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load BPF objects: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	log.Println("eBPF objects loaded successfully.")

	// --- Attach eBPF using netlink (more robust for TC) ---

	// Get the netlink handle for the interface
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		log.Fatalf("failed to get link by index %d: %v", iface.Index, err)
	}

	// Ensure the clsact qdisc exists. This is a special qdisc
	// that allows attaching programs to ingress/egress hooks.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0), // Root qdisc handle for clsact
			Parent:    qdiscParent,                   // Indicate clsact parent
		},
		QdiscType: "clsact", // The type of qdisc
	}

	// Attempt to replace the qdisc. If it doesn't exist, it will be added.
	// If it exists, it will be replaced (idempotent).
	if err := netlink.QdiscReplace(qdisc); err != nil {
		log.Fatalf("failed to replace clsact qdisc on interface %s: %v", link.Attrs().Name, err)
	}
	log.Printf("Ensured clsact qdisc exists on %s\n", link.Attrs().Name)

	// Create the BPF filter (TC program attachment)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    attachPoint, // Attach to ingress hook
			Handle:    netlink.MakeHandle(0, 1), // Unique handle for the filter
			Protocol:  syscall.ETH_P_ALL,         // Process all Ethernet protocols
			Priority:  1,                         // Priority of the filter
		},
		Fd:           objs.TcAggregate.FD(), // File descriptor of the loaded eBPF program
		Name:         "tc_aggregator",       // Name for the filter
		DirectAction: true,                  // Use direct-action mode (modern TC BPF)
	}

	// Replace the filter. This will add it if it doesn't exist or update it.
	if err = netlink.FilterReplace(filter); err != nil {
		log.Fatalf("failed to replace tc filter on interface %s: %v", link.Attrs().Name, err)
	}
	log.Printf("eBPF program attached to %s ingress\n", link.Attrs().Name)

	// Cleanup function to detach the filter and qdisc
	cleanup := func() {
		log.Println("Detaching eBPF program and cleaning up...")
		// Best effort cleanup
		_ = netlink.FilterDel(filter)
		// You might want to conditionally delete the qdisc if nothing else uses it
		// _ = netlink.QdiscDel(qdisc)
		log.Println("Cleanup complete.")
	}
	defer cleanup() // Ensure cleanup happens even on panic

	// --- Signal Handling ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Aggregator started. Press Ctrl+C to stop.")

	// --- Periodic Map Reading ---
	ticker := time.NewTicker(5 * time.Second) // Read map every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := printMapContents(objs.IpStats); err != nil {
				log.Printf("Error reading map: %v", err)
			}
		case <-stop:
			log.Println("Received stop signal.")
			return // Exit the loop and trigger deferred cleanup
		}
	}
}

// printMapContents iterates over the eBPF map and prints its contents.
func printMapContents(statsMap *ebpf.Map) error {
	fmt.Println("\n--- Traffic Stats ---")
	var (
		key   uint32 // Corresponds to __u32 in C
		value uint64 // Corresponds to __u64 in C
	)
	iter := statsMap.Iterate()

	foundEntries := false
	for iter.Next(&key, &value) {
		foundEntries = true
		ip := uint32ToIP(key) // Convert uint32 (network byte order) to net.IP
		fmt.Printf("  %-15s : %d bytes\n", ip.String(), value)
	}

	if !foundEntries {
		fmt.Println("  No traffic captured yet.")
	}
	fmt.Println("---------------------")

	return iter.Err()
}

// uint32ToIP converts a uint32 IP address (network byte order) to a net.IP.
func uint32ToIP(ipUint32 uint32) net.IP {
	ip := make(net.IP, 4)
	// IP addresses in eBPF maps are often stored in network byte order (BigEndian)
	binary.BigEndian.PutUint32(ip, ipUint32)
	return ip
}

// --- Helper to attach TC using cilium/ebpf/link (Alternative) ---
// This is simpler but might be less robust than direct netlink usage for TC.
// Kept here for reference.
func attachTCWithLink(iface *net.Interface, prog *ebpf.Program) (link.Link, error) {
	// Attach the program to the network interface's ingress hook.
	// Using link.AttachTCX for modern TC attachments.
	// It handles creating the clsact qdisc automatically if needed.
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCIngress, // Attach to ingress
		Interface: iface.Index,
	})

	if err != nil {
		// Fallback or older kernel might need AttachTC
		// tcLink, err = link.AttachTC(link.TCOptions{
		//  Program:   prog,
		//  Attach:    ebpf.AttachTCFilter, // Use filter type
		//  Interface: iface.Index,
		//  Handle: 1, // requires parent handle if not clsact
		//  Priority: 1,
		// })
		// if err != nil {
		return nil, fmt.Errorf("failed to attach TC program: %w", err)
		// }
	}
	log.Printf("eBPF program attached to %s ingress (using cilium/link)\n", iface.Name)
	return tcLink, nil
}

// Dummy loadBpfObjects function to satisfy the compiler if bpf2go hasn't run
// This will be replaced by the generated code.
// var loadBpfObjects func(*bpfObjects, *ebpf.CollectionOptions) error

// Dummy bpfObjects struct
// This will be replaced by the generated code.
// type bpfObjects struct {
// 	IpStats    *ebpf.Map     `ebpf:"ip_stats"`
// 	TcAggregate *ebpf.Program `ebpf:"tc_aggregate"`
//  // Add close method if needed manually, bpf2go adds it
//  Close() error
// }
