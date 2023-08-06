package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type CalledContext struct {
	Pc uint64
	By uint64
	SkbLocation
}

type SkbLocation struct {
	OnStack      bool
	OffsetFromBp uint64
	Register     uint8
}

func attachBpfHelpers(prog *ebpf.Program, locationMap *ebpf.Map) (err error) {
	helpers, err := findBpfHelpers()
	if err != nil {
		return
	}
	for name, contexts := range helpers {
		kp, err := link.Kprobe(name, prog, nil)
		if err != nil {
			return err
		}
		defer kp.Close()
		for _, ctx := range contexts {
			called := struct {
				Pc uint64
				By uint64
			}{
				Pc: ctx.Pc,
				By: ctx.By,
			}
			locationMap.Update(called, ctx.SkbLocation, ebpf.UpdateNoExist)
		}
	}
	return
}

// TODO: use cilium/ebpf to list programs
// - bpftool -j p
// - cat /proc/kallsyms
// - bpftool -j p d i $id
// - find all call insns, calc target function, figure out pc, by, name
// - anal %rdi location, figure out its SkbLocation
func findBpfHelpers() (helpers map[string][]CalledContext, err error) {
	return
}
