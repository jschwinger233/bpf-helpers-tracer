package main

import (
	"fmt"

	"github.com/jschwinger233/bpf-helpers-tracer/bpf"
	"github.com/jschwinger233/bpf-helpers-tracer/kernel"
)

func printf(targetSymbol string, event bpf.BpfEvent) {
	switch event.Type {
	case 0: // fentry
		fmt.Printf("> %x %s+0\n", event.Skb, targetSymbol)
	case 1: // fexit
		fmt.Printf("< %x %s\n", event.Skb, targetSymbol)
	case 2: // kprobe
		by := kernel.NearestSymbol(event.By)
		fmt.Printf("> %x %s %s()\n",
			event.Skb,
			fmt.Sprintf("%s+%d", by.Name, event.By-by.Addr),
			kernel.NearestSymbol(event.Pc).Name)
	}
}
