package main

import (
	"encoding/binary"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type IPStats struct {
	IP    string
	Bytes uint64
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang traffic traffic.c -- -I/usr/include/x86_64-linux-gnu

func main() {
	if len(os.Args) < 3 || os.Args[1] != "-iface" {
		log.Fatal("请指定网络接口，例如: -iface eth0")
	}

	ifaceName := os.Args[2]
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("获取网络接口失败: %v", err)
	}

	objs := trafficObjects{}
	if err := loadTrafficObjects(&objs, nil); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()

	prog := objs.TrafficMonitor
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode, // 使用通用模式以提高兼容性
	})
	if err != nil {
		log.Fatalf("附加 XDP 程序失败: %v", err)
	}
	defer xdpLink.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var stats []IPStats
		var key uint32
		var value uint64

		iter := objs.IpStats.Iterate()
		for iter.Next(&key, &value) {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, key)
			stats = append(stats, IPStats{
				IP:    ip.String(),
				Bytes: value,
			})
		}

		tmpl := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>IP 流量统计</title>
			<meta charset="utf-8">
			<style>
				body { font-family: Arial, sans-serif; margin: 40px; }
				table { border-collapse: collapse; width: 100%; }
				th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
				th { background-color: #f2f2f2; }
				tr:nth-child(even) { background-color: #f9f9f9; }
				tr:hover { background-color: #f5f5f5; }
				.refresh { margin-bottom: 20px; }
			</style>
			<script>
				function autoRefresh() {
					setTimeout(function() {
						location.reload();
					}, 5000);
				}
				window.onload = autoRefresh;
			</script>
		</head>
		<body>
			<h1>IP 流量统计</h1>
			<div class="refresh">每5秒自动刷新</div>
			<table>
				<tr>
					<th>IP 地址</th>
					<th>流量 (字节)</th>
				</tr>
				{{range .}}
				<tr>
					<td>{{.IP}}</td>
					<td>{{.Bytes}}</td>
				</tr>
				{{end}}
			</table>
		</body>
		</html>
		`

		t := template.Must(template.New("stats").Parse(tmpl))
		t.Execute(w, stats)
	})

	go func() {
		log.Printf("Web 服务器启动在 http://localhost:8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Web 服务器启动失败: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}