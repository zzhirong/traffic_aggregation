deps:
	sudo apt install linux-headers-$(uname -r)

generate:
	go generate

build:
	go build -o traffic-aggregator
run:
	sudo ./traffic-aggregator -iface eth0
