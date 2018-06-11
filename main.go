package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"

	"github.com/bnagy/gapstone"
)

func main() {

	f, err := elf.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_32,
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, s := range f.Sections {

		fmt.Printf("\nSECTION %s\n", s.Name)

		data, _ := s.Data()
		if len(data) == 0 {
			continue
		}

		insns, err := engine.Disasm(
			[]byte(data), // code buffer
			0x000,        // starting address
			0,            // insns to disassemble, 0 for all
		)
		if err != nil {
			log.Fatal(err)
		}

		for _, insn := range insns {
			fmt.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		}
	}
}
