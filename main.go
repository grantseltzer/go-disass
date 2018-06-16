package main

import (
	"fmt"
	"log"
	"os"
)

func main() {

	disassembler := NewDisassembler()
	disassembler.Open(os.Args[1])
	defer disassembler.File.Close()

	err := disassembler.StartEngineX86_64() // vroom vroom
	if err != nil {
		log.Fatal(err)
	}
	defer disassembler.Engine.Close()

	symbols, err := disassembler.Symbols()
	if err != nil {
		log.Printf("Error getting symbol table: %s\n", err.Error())
	}

	textSection := disassembler.Section(".text")
	if textSection == nil {
		log.Fatal("No text section")
	}

	textData, err := textSection.Data()
	if err != nil {
		log.Fatal(err)
	}

symLoop:
	for _, sym := range symbols {

		// Only care about function symbols
		if sym.Info != byte(2) {
			continue symLoop
		}

		// Don't want no empty symbols!
		if sym.Size == 0 {
			continue symLoop
		}

		symbolLocation := sym.Value - textSection.Addr
		symbolData := []byte{}

		// Loop through textData starting at symbolLocation for symbol.Size bytes
		for _, b := range textData[symbolLocation : symbolLocation+sym.Size] {
			symbolData = append(symbolData, b)
		}

		// Dissasemble the symbol
		symbolInstrucitons, err := disassembler.Disasm(symbolData, sym.Value, 0x0)
		if err != nil {
			continue symLoop //  o well!
		}

		fmt.Printf("\n\nSYMBOL %s\n", sym.Name)
		for _, ins := range symbolInstrucitons {
			fmt.Printf("0x%x:\t%s\t\t%s\n", ins.Address, ins.Mnemonic, ins.OpStr)
		}
	}
}
