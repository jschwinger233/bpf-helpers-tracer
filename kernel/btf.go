package kernel

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/btf"
)

var iters []*btf.TypesIterator

func init() {
	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("failed to load kernel btf: %v", err)
	}

	iters = append(iters, kernelSpec.Iterate())

	path := filepath.Join("/sys/kernel/btf", "vmlinux")
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("failed to open %s: %v", path, err)
	}
	defer f.Close()

	modSpec, err := btf.LoadSplitSpecFromReader(f, kernelSpec)
	if err != nil {
		log.Fatalf("failed to load split btf: %v", err)
	}
	iters = append(iters, modSpec.Iterate())
}

var fnProtos map[string]*btf.FuncProto

func BTFPrepare(funcnames []string) (err error) {
	fnProtos = make(map[string]*btf.FuncProto)

	for _, it := range iters {
		for it.Next() {
			fn, ok := it.Type.(*btf.Func)
			if !ok {
				continue
			}

			fnProto, ok := fn.Type.(*btf.FuncProto)
			if ok {
				fnProtos[fn.Name] = fnProto
			}
		}
	}

	return
}

func BTFFormat(fname string, args [6]uint64) string {
	fnProto, ok := fnProtos[fname]
	if !ok {
		return ""
	}

	buf := []string{}
	for idx, param := range fnProto.Params {
		buf = append(buf, fmt.Sprintf("%s=%d", param.Name, args[idx]))
	}
	return strings.Join(buf, ", ")
}
