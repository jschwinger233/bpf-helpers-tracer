// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfArgs struct {
	Skb uint64
	Arg [6]uint64
}

type BpfContent struct {
	Skb   uint64
	Bytes [64]uint8
}

type BpfDatum struct {
	Skb     uint64
	Mark    uint32
	Payload [256]uint8
	_       [4]byte
}

type BpfEvent struct {
	Ts   uint64
	Skb  uint64
	Pc   uint64
	By   uint64
	Type uint8
	_    [7]byte
}

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
}

// BpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	OffBpfHelper   *ebpf.ProgramSpec `ebpf:"off_bpf_helper"`
	OffTcfClassify *ebpf.ProgramSpec `ebpf:"off_tcf_classify"`
	OnBpfHelper    *ebpf.ProgramSpec `ebpf:"on_bpf_helper"`
	OnEntry        *ebpf.ProgramSpec `ebpf:"on_entry"`
	OnExit         *ebpf.ProgramSpec `ebpf:"on_exit"`
	OnTcfClassify  *ebpf.ProgramSpec `ebpf:"on_tcf_classify"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	Argsbuf    *ebpf.MapSpec `ebpf:"argsbuf"`
	Bp2skb     *ebpf.MapSpec `ebpf:"bp2skb"`
	Contentbuf *ebpf.MapSpec `ebpf:"contentbuf"`
	Data       *ebpf.MapSpec `ebpf:"data"`
	Events     *ebpf.MapSpec `ebpf:"events"`
	Pc2param   *ebpf.MapSpec `ebpf:"pc2param"`
	Skbmatched *ebpf.MapSpec `ebpf:"skbmatched"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	Argsbuf    *ebpf.Map `ebpf:"argsbuf"`
	Bp2skb     *ebpf.Map `ebpf:"bp2skb"`
	Contentbuf *ebpf.Map `ebpf:"contentbuf"`
	Data       *ebpf.Map `ebpf:"data"`
	Events     *ebpf.Map `ebpf:"events"`
	Pc2param   *ebpf.Map `ebpf:"pc2param"`
	Skbmatched *ebpf.Map `ebpf:"skbmatched"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.Argsbuf,
		m.Bp2skb,
		m.Contentbuf,
		m.Data,
		m.Events,
		m.Pc2param,
		m.Skbmatched,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	OffBpfHelper   *ebpf.Program `ebpf:"off_bpf_helper"`
	OffTcfClassify *ebpf.Program `ebpf:"off_tcf_classify"`
	OnBpfHelper    *ebpf.Program `ebpf:"on_bpf_helper"`
	OnEntry        *ebpf.Program `ebpf:"on_entry"`
	OnExit         *ebpf.Program `ebpf:"on_exit"`
	OnTcfClassify  *ebpf.Program `ebpf:"on_tcf_classify"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.OffBpfHelper,
		p.OffTcfClassify,
		p.OnBpfHelper,
		p.OnEntry,
		p.OnExit,
		p.OnTcfClassify,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel_x86.o
var _BpfBytes []byte
