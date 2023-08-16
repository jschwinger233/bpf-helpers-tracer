package main

import (
	"context"
	"strings"

	flag "github.com/spf13/pflag"

	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/bpf-helpers-tracer/bpf"
	"github.com/jschwinger233/bpf-helpers-tracer/kernel"
)

var (
	targetID int
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	flag.IntVar(&targetID, "prog-id", -1, "(required) only support tc-bpf program for now")
	flag.Parse()
	if targetID == -1 {
		flag.PrintDefaults()
	}
	pcapFilter := strings.Join(flag.Args(), " ")

	targetSymbol, err := kernel.BpfProgSymbol(targetID)
	if err != nil {
		log.Fatal(err)
	}

	b, err := bpf.New(ctx, targetID)
	if err != nil {
		log.Fatal(err)
	}

	b.InjectPcapFilter(pcapFilter)

	detach, err := b.Attach(targetID)
	if err != nil {
		log.Fatal(err)
	}
	defer detach()

	kernel.RefreshKallsyms()

	fmt.Printf("Start tracing\n")
	for event := range b.PollEvents(ctx) {
		printf(targetSymbol, event)
	}

	/*
		Next:
		5. pcap-filter code cleanup
		4. output skb brief info (only for fentry/fexit, higtlight diff)
		6. function arguments (not that hard)

		7. why some functions are traced even before fentry?
	*/
}
