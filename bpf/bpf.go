package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event -type skbmeta Bpf ./bpf.c -- -I./headers -I. -Wall

func T() {
	println()
}
