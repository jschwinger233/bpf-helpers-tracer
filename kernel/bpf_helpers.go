package kernel

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
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
	Src       string   `json:"src"`
}

type ProgDetail struct {
	Name  string `json:"name"`
	Insns []Ins  `json:"insns"`
}

type BpfSource struct {
	Pc  uint64
	Src string
}

var bpfSources = map[string][]BpfSource{}

func GetHelpersFromBpfPrograms(ctx context.Context) (helpers []string, err error) {
	data, err := exec.Command("bpftool", "-j", "p", "l").Output()
	if err != nil {
		return nil, err
	}
	progs := []Prog{}
	if err = json.Unmarshal(data, &progs); err != nil {
		return
	}

	mux := &sync.Mutex{}
	mux2 := &sync.Mutex{}
	called := map[string]interface{}{}
	sem := semaphore.NewWeighted(16)
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
				return
			}
			pd := []ProgDetail{}
			if err := json.Unmarshal(d, &pd); err != nil {
				log.Printf("Unmarshal %s failed: %s", string(d), err)
				return
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
					mux.Lock()
					called[NearestSymbol(targetAddr).Name] = nil
					mux.Unlock()
				}

				if ins.Src != "" {
					pc := strings.TrimPrefix(ins.Pc, "0x")
					p, err := strconv.ParseUint(pc, 16, 64)
					if err != nil {
						log.Println(err)
					}
					mux2.Lock()
					bpfSources[pd[0].Name] = append(bpfSources[pd[0].Name], BpfSource{
						Pc:  p,
						Src: ins.Src,
					})
					mux2.Unlock()
				}
			}
		}(prog)
	}

	sem.Acquire(ctx, 16)

	for funcname := range called {
		helpers = append(helpers, funcname)
	}
	return
}

func BpfSrc(prog string, pc uint64) string {
	sources, ok := bpfSources[prog]
	if !ok {
		return ""
	}
	idx, _ := slices.BinarySearchFunc(sources, pc, func(x BpfSource, pc uint64) int { return int(x.Pc - pc) })
	return sources[idx-1].Src
}
