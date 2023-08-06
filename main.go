package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/bpf-helpers-tracer/bpf"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	spec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatal(err)
	}

	progID, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		log.Fatal(err)
	}
	targetInfo, err := targetProg.Info()
	if err != nil {
		log.Fatal(err)
	}
	spec.Programs["on_entry"].AttachTarget = targetProg
	spec.Programs["on_entry"].AttachTo, err = targetInfo.Fullname()
	spec.Programs["on_exit"].AttachTarget = targetProg
	spec.Programs["on_exit"].AttachTo, err = targetInfo.Fullname()

	objs := bpf.BpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load and assign programs: %v\n%s", err, verifierLog)
	}
	defer objs.Close()

	if err = attachBpfHelpers(objs.OnBpfHelper, objs.SkbLocations); err != nil {
		log.Fatal(err)
	}

	fentry, err := link.AttachTracing(link.TracingOptions{
		Program: objs.BpfPrograms.OnEntry,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer fentry.Close()

	fexit, err := link.AttachTracing(link.TracingOptions{
		Program: objs.BpfPrograms.OnExit,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer fexit.Close()

	rd, err := ringbuf.NewReader(objs.BpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	var event bpf.BpfEvent
	for {
		println("reading")
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("%+v\n", event)
	}

	<-stopper

	// next steps:
	// 1. fentry events and parsing
	// 2. pcap filter
	// 3. bpf helpers
	// 4. skb meta
}
