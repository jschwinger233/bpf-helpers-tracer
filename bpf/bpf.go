package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/bpf-helpers-tracer/kernel"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event -type datum -type args -type content Bpf ./bpf.c -- -I./headers -I. -Wall
type Bpf struct {
	spec *ebpf.CollectionSpec
	objs *BpfObjects

	helpers    []string
	params     map[uint64][6]bool
	TargetName string
}

type Event struct {
	BpfEvent
	BpfDatum
	BpfArgs
	Contents [6]BpfContent
}

func New(ctx context.Context, progID int) (b *Bpf, err error) {
	b = &Bpf{
		objs:   &BpfObjects{},
		params: make(map[uint64][6]bool),
	}
	if b.helpers, err = kernel.GetHelpersFromBpfPrograms(ctx); err != nil {
		return
	}
	if err = kernel.BTFPrepare(); err != nil {
		return
	}
	if b.spec, err = LoadBpf(); err != nil {
		return
	}
	return
}

func (b *Bpf) InjectPcapFilter(filter string) (err error) {
	return InjectPcapFilter(b.spec.Programs["on_entry"], filter)
}

func (b *Bpf) setMapsKV() (err error) {
	for _, helper := range b.helpers {
		proto := kernel.BTFGetFuncProto(helper)
		if proto == nil {
			continue
		}
		isPtr := [6]bool{}
		for idx, param := range proto.Params {
			if idx >= 6 {
				break
			}
			switch param.Name {
			case "skb", "map", "key", "value":
				isPtr[idx] = true
			default:
				_, isPtr[idx] = param.Type.(*btf.Pointer)
			}
		}
		pc := kernel.Kaddr(helper)
		b.objs.Pc2param.Update(pc+1, isPtr, ebpf.UpdateNoExist)
		b.params[pc+1] = isPtr
	}
	return
}

func (b *Bpf) Attach(targetID int) (_ func(), err error) {
	if b.TargetName, err = b.adjustSpec(targetID); err != nil {
		return
	}

	if err := b.spec.LoadAndAssign(b.objs, nil); err != nil {
		ve := &ebpf.VerifierError{}
		if errors.As(err, &ve) {
			return nil, ve
		}
		return nil, err
	}

	if err = b.setMapsKV(); err != nil {
		return
	}

	detach, err := b.attach()
	if err != nil {
		return nil, err
	}
	return func() {
		detach()
		b.objs.Close()
	}, nil
}

func (b *Bpf) adjustSpec(targetID int) (targetName string, err error) {
	targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(targetID))
	if err != nil {
		return
	}
	targetInfo, err := targetProg.Info()
	if err != nil {
		return
	}
	if targetName, err = targetInfo.Fullname(); err != nil {
		return
	}
	b.spec.Programs["on_entry"].AttachTarget = targetProg
	b.spec.Programs["on_entry"].AttachTo = targetName
	b.spec.Programs["on_exit"].AttachTarget = targetProg
	b.spec.Programs["on_exit"].AttachTo = targetName
	return targetName, nil
}

func (b *Bpf) attach() (detach func(), err error) {
	detaches := make([]func(), 6)

	if detaches[0], err = b.attachHelpersEntry(); err != nil {
		return
	}

	if detaches[1], err = b.attachHelpersExit(); err != nil {
		return
	}

	if detaches[2], err = b.attachTargetEntry(); err != nil {
		return
	}

	if detaches[3], err = b.attachTargetExit(); err != nil {
		return
	}

	if detaches[4], err = b.attachFamousCallerEntry(); err != nil {
		return
	}

	if detaches[5], err = b.attachFamousCallerExit(); err != nil {
		return
	}

	return func() {
		for _, detach := range detaches {
			detach()
		}
	}, nil
}

func (b *Bpf) attachHelpersEntry() (detach func(), err error) {
	kps := []link.Link{}
	for _, helper := range b.helpers {
		kp, err := link.Kprobe(helper, b.objs.OnBpfHelper, nil)
		if err != nil {
			log.Printf("Warn: failed to attach kprobe %s: %+v", helper, err)
			continue
		}
		kps = append(kps, kp)
	}
	return func() {
		for _, kp := range kps {
			kp.Close()
		}
	}, nil
}

func (b *Bpf) attachHelpersExit() (detach func(), err error) {
	// disable kretprobe for now
	return func() {}, nil
	krps := []link.Link{}
	for _, helper := range b.helpers {
		krp, err := link.Kretprobe(helper, b.objs.OffBpfHelper, nil)
		if err != nil {
			log.Printf("Warn: failed to attach kprobe %s: %+v", helper, err)
			continue
		}
		krps = append(krps, krp)
	}
	return func() {
		for _, krp := range krps {
			krp.Close()
		}
	}, nil
}

func (b *Bpf) attachTargetEntry() (detach func(), err error) {
	fentry, err := link.AttachTracing(link.TracingOptions{
		Program: b.objs.OnEntry,
	})
	return func() { fentry.Close() }, err
}

func (b *Bpf) attachTargetExit() (detach func(), err error) {
	fexit, err := link.AttachTracing(link.TracingOptions{
		Program: b.objs.OnExit,
	})
	return func() { fexit.Close() }, err
}

func (b *Bpf) attachFamousCallerEntry() (detach func(), err error) {
	kp, err := link.Kprobe("tcf_classify", b.objs.OnTcfClassify, nil)
	return func() { kp.Close() }, err
}

func (b *Bpf) attachFamousCallerExit() (detach func(), err error) {
	krp, err := link.Kretprobe("tcf_classify", b.objs.OffTcfClassify, nil)
	return func() { krp.Close() }, err
}

func (b *Bpf) PollEvents(ctx context.Context) <-chan Event {
	ch := make(chan Event)

	go func() {
		defer close(ch)

		eventReader, err := ringbuf.NewReader(b.objs.Events)
		if err != nil {
			log.Printf("Failed to open ringbuf: %+v", err)
		}
		defer eventReader.Close()

		dataReader, err := ringbuf.NewReader(b.objs.Data)
		if err != nil {
			log.Printf("Failed to open ringbuf: %+v", err)
		}
		defer dataReader.Close()

		argsReader, err := ringbuf.NewReader(b.objs.Argsbuf)
		if err != nil {
			log.Printf("Failed to open ringbuf: %+v", err)
		}
		defer argsReader.Close()

		contentReader, err := ringbuf.NewReader(b.objs.Contentbuf)
		if err != nil {
			log.Printf("Failed to open ringbuf: %+v", err)
		}
		defer contentReader.Close()

		go func() {
			<-ctx.Done()
			eventReader.Close()
			dataReader.Close()
			argsReader.Close()
			contentReader.Close()
		}()

		for {
			var event Event
			record, err := eventReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Failed to read ringbuf: %+v", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event.BpfEvent); err != nil {
				log.Printf("Failed to parse ringbuf event: %+v", err)
				continue
			}

			switch event.Type {

			// get skb payload for fentry and fexit
			case 0, 1:
				if record, err = dataReader.Read(); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Failed to read ringbuf: %+v", err)
					continue
				}

				if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event.BpfDatum); err != nil {
					log.Printf("Failed to parse ringbuf data: %+v", err)

				}

				if event.BpfEvent.Skb != event.BpfDatum.Skb {
					log.Printf("Failed to match skb pointers: %x != %x", event.BpfEvent.Skb, event.BpfDatum.Skb)
				}

				// get bpf-helpers' arguments for kprobes
			case 2, 3:
				if record, err = argsReader.Read(); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Failed to read ringbuf: %+v", err)
					continue
				}

				if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event.BpfArgs); err != nil {
					log.Printf("Failed to parse ringbuf args: %+v", err)
				}

				if event.BpfEvent.Skb != event.BpfArgs.Skb {
					log.Printf("Failed to match skb pointers: %x != %x", event.BpfEvent.Skb, event.BpfArgs.Skb)
				}

				// get pointer content
				for idx, isPtr := range b.params[event.Pc] {
					if !isPtr {
						continue
					}
					if record, err = contentReader.Read(); err != nil {
						if errors.Is(err, ringbuf.ErrClosed) {
							return
						}
						log.Printf("Failed to read ringbuf: %+v", err)
						continue
					}

					if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event.Contents[idx]); err != nil {
						log.Printf("Failed to parse ringbuf args: %+v", err)
					}

					if event.BpfEvent.Skb != event.Contents[idx].Skb {
						log.Printf("Failed to match skb pointers: %x != %x", event.BpfEvent.Skb, event.BpfArgs.Skb)
					}
				}
			}

			ch <- event
		}
	}()

	return ch
}
