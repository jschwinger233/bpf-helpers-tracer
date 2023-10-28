module github.com/jschwinger233/bpf-helpers-tracer

go 1.20

require (
	github.com/cilium/ebpf v0.12.2
	github.com/cloudflare/cbpfc v0.0.0-20231012060448-992ed7573b5c
	github.com/google/gopacket v1.1.19
	github.com/spf13/pflag v1.0.5
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	golang.org/x/net v0.17.0
	golang.org/x/sync v0.4.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

// https://github.com/jschwinger233/ebpf/tree/gray/full-name
replace github.com/cilium/ebpf v0.12.2 => github.com/jschwinger233/ebpf v0.9.2-0.20230817102944-95a659894770
