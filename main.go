package main

import (
	"encoding/binary"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	humanize "github.com/dustin/go-humanize"
)

type IPStats struct {
	IP    string
	Bytes uint64
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang traffic traffic.c -- -I/usr/include/x86_64-linux-gnu
var tmpl = `
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
					<td>{{formatBytes .Bytes}}</td>
				</tr>
				{{end}}
			</table>
		</body>
		</html>
		`
func formatBytes(bytes uint64) string{
	return humanize.Bytes(bytes)
}

func main() {
	var ifaceName string
	var limit int
	flag.StringVar(&ifaceName, "iface", "eth0", "网络接口名称，例如: eth0")
	flag.IntVar(&limit, "n", 30, "显示前n个流量最高的IP地址")
	flag.Parse()

	if ifaceName == "" {
		log.Fatal("请指定网络接口，例如: -iface eth0 -n 30")
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("获取网络接口失败: %v", err)
	}

	objs := trafficObjects{}
	if err = loadTrafficObjects(&objs, nil); err != nil {
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

	t := template.Must(template.New("stats").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
	}).Parse(tmpl))
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

		// 按Bytes降序排序
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].Bytes > stats[j].Bytes
		})

		// 只保留前limit个结果
		if len(stats) > limit {
			stats = stats[:limit]
		}

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
