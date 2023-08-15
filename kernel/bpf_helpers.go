package kernel

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
)

type Prog struct {
	Id   int    `json:"id"`
	Type string `json:"type"`
}

type Ins struct {
	Pc        string   `json:"pc"`
	Operation string   `json:"operation"`
	Opcodes   []string `json:"opcodes"`
}

type ProgDetail struct {
	Name  string `json:"name"`
	Insns []Ins  `json:"insns"`
}

func GetHelpersFromBpfPrograms() (helpers []string, err error) {
	data, err := exec.Command("bpftool", "-j", "p", "l").Output()
	if err != nil {
		return nil, err
	}
	progs := []Prog{}
	if err = json.Unmarshal(data, &progs); err != nil {
		return
	}

	called := map[string]interface{}{}
	for _, prog := range progs {
		if prog.Type != "sched_cls" {
			continue
		}
		if prog.Id == 861 {
			println()
		}
		d, err := exec.Command("bpftool", "-j", "p", "d", "j", "i", strconv.Itoa(prog.Id), "opcode").Output()
		if err != nil {
			return nil, err
		}
		pd := []ProgDetail{}
		if err := json.Unmarshal(d, &pd); err != nil {
			return nil, err
		}
		base := Kaddr(pd[0].Name)
		for _, ins := range pd[0].Insns {
			if ins.Operation == "callq" {
				targetAddr := uint64(0)
				for i := 4; i > 0; i-- {
					targetAddr <<= 8
					opcode := strings.TrimPrefix(ins.Opcodes[i], "0x")
					a, err := strconv.ParseUint(opcode, 16, 64)
					if err != nil {
						return nil, err
					}
					targetAddr += a
				}
				pc := strings.TrimPrefix(ins.Pc, "0x")
				p, err := strconv.ParseUint(pc, 16, 64)
				if err != nil {
					return nil, err
				}
				targetAddr += p + 5 + base
				if targetAddr < p+5+base {
					targetAddr -= 1 << 32
				}
				called[NearestSymbol(targetAddr).Name] = nil
			}
		}
	}

	for funcname := range called {
		helpers = append(helpers, funcname)
	}
	return
}
