package kernel

import (
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

type Symbol struct {
	Name string
	Addr uint64
}

var kallsyms []Symbol

func init() {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, " ")
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		name := parts[2]
		kallsyms = append(kallsyms, Symbol{name, addr})
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func NearestSymbol(addr uint64) string {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int { return int(x.Addr - addr) })
	return kallsyms[idx-1].Name
}
