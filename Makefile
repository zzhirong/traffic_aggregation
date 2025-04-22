.PHONY: deps generate build run clean test help

help:
	@echo "可用的 make 命令："
	@echo "  deps     - 安装系统依赖"
	@echo "  generate - 生成 eBPF 代码"
	@echo "  build    - 构建项目"
	@echo "  run      - 运行项目（默认使用 eth0 接口）"
	@echo "  test     - 运行测试"
	@echo "  clean    - 清理编译文件"

deps:
	@echo "正在安装系统依赖..."
	sudo apt-get update
	sudo apt-get install --reinstall -y linux-headers-$(uname -r) linux-libc-dev llvm clang libbpf-dev

# 编译 eBPF 程序
generate:
	go generate

# 构建项目
build: generate
	go build -o traffic-aggregator

# 运行项目
run: build
	@echo "正在启动流量统计..."
	sudo ./traffic-aggregator -iface eth0

# 运行测试
test:
	@echo "正在运行测试..."
	go test ./...

# 清理编译文件
clean:
	@echo "正在清理编译文件..."
	rm -f traffic-aggregator
	rm -f *.o
