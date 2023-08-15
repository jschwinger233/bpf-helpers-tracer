package main

import (
	"fmt"

	"github.com/jschwinger233/bpf-helpers-tracer/bpf"
	"github.com/jschwinger233/bpf-helpers-tracer/kernel"
)

func printf(b *bpf.Bpf, event bpf.BpfEvent) {
	switch event.Type {
	case 0:
		fmt.Printf("-> %s\n", b.TargetName)
	case 1:
		fmt.Printf("<- %s\n", b.TargetName)
	case 2:
		fmt.Printf("-> %s\n", kernel.NearestSymbol(event.Pc).Name)
	case 4:
		fmt.Printf("<- %s\n", kernel.NearestSymbol(event.Pc).Name)
	}
}
