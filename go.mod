module github.com/Diniboy1123/usque

go 1.27.1

require (
	codeberg.org/miekg/dns v0.6.115
	github.com/Diniboy1123/connect-ip-go v0.0.0-20260613064811-66cba32d7d33
	github.com/quic-go/quic-go v0.63.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/spf13/cobra v1.10.2
	github.com/txthinking/runnergroup v0.0.0-20250224021307-5864ffeb65ae
	github.com/txthinking/socks5 v0.0.0-20260601051520-339b044ab0eb
	github.com/vishvananda/netlink v1.3.1
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	gvisor.dev/gvisor v0.0.0-20260616165937-8e4bc62602eb
)

require (
	github.com/dunglas/httpsfv v1.1.2 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/Diniboy1123/connect-ip-go => ./third_party/connect-ip-go
