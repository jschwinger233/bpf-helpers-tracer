package bpf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

/*
#cgo LDFLAGS: -L/usr/local/lib -lpcap -static
#include <stdlib.h>
#include <pcap.h>
*/
import "C"

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144
)

func CompileCbpf(expr string) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	pcap := C.pcap_open_dead(C.DLT_EN10MB, MAXIMUM_SNAPLEN)
	if pcap == nil {
		return nil, fmt.Errorf("failed to pcap_open_dead: %+v\n", C.PCAP_ERROR)
	}
	defer C.pcap_close(pcap)

	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var bpfProg pcapBpfProgram
	if C.pcap_compile(pcap, (*C.struct_bpf_program)(&bpfProg), cexpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, fmt.Errorf("failed to pcap_compile '%s': %+v", expr, C.GoString(C.pcap_geterr(pcap)))
	}
	defer C.pcap_freecode((*C.struct_bpf_program)(&bpfProg))

	for _, v := range (*[bpfInstructionBufferSize]C.struct_bpf_insn)(unsafe.Pointer(bpfProg.bf_insns))[0:bpfProg.bf_len:bpfProg.bf_len] {
		insts = append(insts, bpf.RawInstruction{
			Op: uint16(v.code),
			Jt: uint8(v.jt),
			Jf: uint8(v.jf),
			K:  uint32(v.k),
		}.Disassemble())
	}
	return
}

func CompileEbpf(expr string, opts cbpfc.EBPFOpts) (insts asm.Instructions, err error) {
	cbpfInsts, err := CompileCbpf(expr)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, opts)
	if err != nil {
		return
	}

	return adjustEbpf(ebpfInsts, opts)
}

func adjustEbpf(insts asm.Instructions, opts cbpfc.EBPFOpts) (newInsts asm.Instructions, err error) {
	replaceIdx := []int{}
	replaceInsts := map[int]asm.Instructions{}
	for idx, inst := range insts {
		if inst.OpCode.Class().IsLoad() {
			replaceIdx = append(replaceIdx, idx)
			replaceInsts[idx] = append(replaceInsts[idx],

				asm.StoreMem(asm.RFP, -32, asm.R1, asm.DWord),
				asm.StoreMem(asm.RFP, -40, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, -48, asm.R3, asm.DWord),

				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -24),
				asm.Mov.Imm(asm.R2, int32(inst.OpCode.Size().Sizeof())),
				asm.Mov.Reg(asm.R3, inst.Src),
				asm.Add.Imm(asm.R3, int32(inst.Offset)),
				asm.FnProbeReadKernel.Call(),

				asm.LoadMem(inst.Dst, asm.RFP, -24, inst.OpCode.Size()),
			)

			restoreInsts := asm.Instructions{
				asm.LoadMem(asm.R1, asm.RFP, -32, asm.DWord),
				asm.LoadMem(asm.R2, asm.RFP, -40, asm.DWord),
				asm.LoadMem(asm.R3, asm.RFP, -48, asm.DWord),
			}
			switch inst.Dst {
			case asm.R1, asm.R2, asm.R3:
				restoreInsts = append(restoreInsts[:inst.Dst-1], restoreInsts[inst.Dst:]...)
			}
			replaceInsts[idx] = append(replaceInsts[idx], restoreInsts...)

			replaceInsts[idx][0].Metadata = inst.Metadata
		}
	}

	for i := len(replaceIdx) - 1; i >= 0; i-- {
		idx := replaceIdx[i]
		insts = append(insts[:idx], append(replaceInsts[idx], insts[idx+1:]...)...)
	}

	insts = append([]asm.Instruction{
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Imm(asm.R3, 0),
	}, insts...)

	insts = append(insts,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("result"), // r0 = 0
		asm.Mov.Reg(opts.PacketStart, opts.Result),  // skb->data = $result
		asm.Mov.Imm(opts.PacketEnd, 0),              // skb->data_end = 0
	)

	return insts, nil
}

func InjectPcapFilter(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	injectIdx := 0
	for idx, inst := range program.Instructions {
		if inst.OpCode.JumpOp() == asm.Call && inst.Constant == int64(asm.FnTracePrintk) {
			injectIdx = idx
			break
		}

		if inst.OpCode.Class().IsJump() {
			if inst.Offset == 0 {
				continue
			}

			if inst.Reference() != "" {
				program.Instructions[idx].Offset = -1
				continue
			}

			var gotoIns *asm.Instruction
			iter := asm.Instructions(program.Instructions[idx+1:]).Iterate()
			for iter.Next() {
				if int16(iter.Offset) == inst.Offset {
					gotoIns = iter.Ins
					break
				}
			}
			if gotoIns == nil {
				return errors.New("Cannot find the jump target")
			}
			symbol := gotoIns.Symbol()
			if symbol == "" {
				symbol = fmt.Sprintf("pcap_%d", idx)
				*gotoIns = gotoIns.WithSymbol(symbol)
			}
			program.Instructions[idx] = program.Instructions[idx].WithReference(symbol)
			program.Instructions[idx].Offset = -1
		}
	}
	if injectIdx == 0 {
		return errors.New("Cannot find the injection position")
	}

	if filterExpr == "" {
		program.Instructions = append(program.Instructions[:injectIdx],
			program.Instructions[injectIdx+1:]...,
		)
		return
	}

	var (
		dataReg    asm.Register = 255
		dataEndReg asm.Register = 255
	)
	for idx := injectIdx - 1; idx >= 0; idx-- {
		inst := program.Instructions[idx]
		if inst.OpCode.ALUOp() == asm.Mov {
			if inst.Dst == asm.R3 {
				dataReg = inst.Src
			} else if inst.Dst == asm.R4 {
				dataEndReg = inst.Src
			}
		}
		if dataReg != 255 && dataEndReg != 255 {
			break
		}
	}
	if dataReg == 255 || dataEndReg == 255 {
		return errors.New("Cannot find the data / data_end registers")
	}

	filterEbpf, err := CompileEbpf(filterExpr, cbpfc.EBPFOpts{
		PacketStart: dataReg,
		PacketEnd:   dataEndReg,
		Result:      asm.R4,
		ResultLabel: "result",
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "filter",
		StackOffset: 56,
	})
	if err != nil {
		return
	}
	program.Instructions = append(program.Instructions[:injectIdx-4],
		append(filterEbpf, program.Instructions[injectIdx+1:]...)...,
	)

	return nil
}
