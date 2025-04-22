# IP 流量统计工具

这是一个基于 eBPF 技术的网络流量统计工具，可以实时监控网络接口上的 IP 流量，并通过 Web 界面展示统计结果。

## 功能特点

- 使用 eBPF/XDP 技术，高效地监控网络流量
- 统计源 IP 和目标 IP 的流量数据
- 提供实时更新的 Web 界面展示统计结果
- 支持自动刷新数据显示

## 系统要求

### 操作系统
- Linux 操作系统（内核版本 >= 4.18）
  - 需要启用 eBPF 和 XDP 相关内核配置
  - 推荐使用 Ubuntu 20.04 或更新版本

### 编译工具链
- Clang/LLVM（版本 >= 10.0）
  - 用于编译 eBPF 程序
  - Ubuntu 安装命令：`sudo apt install clang llvm`
- Make 工具
  - 用于项目构建
  - Ubuntu 安装命令：`sudo apt install make`

### 开发环境
- Go 开发环境（版本 >= 1.16）
  - 用于编译主程序
  - 从 https://golang.org 下载安装

### 系统库
- libbpf 开发库
  - Ubuntu 安装命令：`sudo apt install libbpf-dev`
- Linux 头文件
  - Ubuntu 安装命令：`sudo apt install linux-headers-$(uname -r)`

## Go 依赖项

- github.com/cilium/ebpf - eBPF 程序加载和管理
- github.com/vishvananda/netlink - 网络接口操作

## 安装步骤(二选一)
1. 从 Relase 页面下载编译好的, 然后运行
2. 克隆项目代码：
```bash
git clone <repository_url>
cd traffic_aggregation && make build
```

## 使用方法

1. 运行程序（需要 root 权限）：
```bash
sudo ./traffic-aggregator -iface <网络接口名称>
```
例如：
```bash
sudo ./traffic-aggregator -iface eth0
```

2. 打开浏览器访问统计界面：
```
http://localhost:8080
```

## Web 界面功能

- 显示所有监控到的 IP 地址及其流量统计
- 每 5 秒自动刷新数据
- 清晰的表格展示，支持鼠标悬停高亮

## 实现原理

1. eBPF 程序（traffic.c）:
   - 使用 XDP（eXpress Data Path）钩子拦截网络数据包
   - 解析数据包获取源 IP 和目标 IP
   - 使用 BPF Map 存储流量统计数据

2. Go 程序（main.go）:
   - 加载和附加 eBPF 程序到指定网络接口
   - 提供 Web 服务器展示统计数据
   - 实现优雅退出机制

## 注意事项

- 程序需要 root 权限才能运行
- 使用通用 XDP 模式以提高兼容性
- 确保指定的网络接口名称正确

## 许可证

本项目采用 MIT 许可证，详细内容请参阅 [LICENSE](LICENSE) 文件。
