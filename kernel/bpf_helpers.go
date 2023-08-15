package kernel

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sync/semaphore"
)

type Prog struct {
	Id   int    `json:"id"`
	Type string `json:"type"`
	Tag  string `json:"tag"`
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

func GetHelpersFromBpfPrograms(ctx context.Context) (helpers []string, err error) {
	data, err := exec.Command("bpftool", "-j", "p", "l").Output()
	if err != nil {
		return nil, err
	}
	progs := []Prog{}
	if err = json.Unmarshal(data, &progs); err != nil {
		return
	}

	called := map[string]interface{}{}
	sem := semaphore.NewWeighted(10)
	for _, prog := range progs {
		if prog.Type != "sched_cls" {
			continue
		}

		sem.Acquire(ctx, 1)
		go func(prog Prog) {
			defer sem.Release(1)

			d, err := exec.Command("bpftool", "-j", "p", "d", "j", "i", strconv.Itoa(prog.Id), "opcode").Output()
			if err != nil {
				log.Println(err)
			}
			pd := []ProgDetail{}
			if err := json.Unmarshal(d, &pd); err != nil {
				log.Println(err)
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
							log.Println(err)
						}
						targetAddr += a
					}
					pc := strings.TrimPrefix(ins.Pc, "0x")
					p, err := strconv.ParseUint(pc, 16, 64)
					if err != nil {
						log.Println(err)
					}
					targetAddr += p + 5 + base
					if targetAddr < p+5+base {
						targetAddr -= 1 << 32
					}
					called[NearestSymbol(targetAddr).Name] = nil
				}
			}
		}(prog)
	}

	sem.Acquire(ctx, 10)

	for funcname := range called {
		helpers = append(helpers, funcname)
	}
	return
}
