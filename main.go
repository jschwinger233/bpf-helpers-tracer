package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"

	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/bpf-helpers-tracer/bpf"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

}

func main() {
	targetID, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	b, err := bpf.New(targetID)
	if err != nil {
		log.Fatal(err)
	}

	detach, err := b.Attach(targetID)
	if err != nil {
		log.Fatal(err)
	}
	defer detach()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for event := range b.PollEvents(ctx) {
		printf(b, event)
	}

	/*
		Next:
		2. attach all functions (by parsing bpf prog opcode)
		3. output more info: called-by, ts, skb
		4. output skb brief info (or output entire skb as pcap?)
		5. pcap-filter
		6. function arguments
	*/
}
