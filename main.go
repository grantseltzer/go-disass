package main

import (
	"debug/elf"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/bnagy/gapstone"
	"github.com/fatih/color"
)

var globalVerbose bool

func main() {

	flag.BoolVar(&globalVerbose, "debug", false, "Debug disassembly")
	flag.Parse()

	disassembler := NewDisassembler()
	disassembler.Open(os.Args[1])
	defer disassembler.f.Close()

	err := disassembler.StartEngineX86_64()
	if err != nil {
		log.Fatal(err)
	}
	defer disassembler.e.Close()

	symbols, err := disassembler.f.Symbols()
	if err != nil {
		log.Printf("Error getting symbol table: %s\n", err.Error())
	}

	// place in map for easy lookup
	symMap := make(map[ /*Address*/ uint64] /*symbol*/ *elf.Symbol)
	for i := range symbols {
		symMap[symbols[i].Value] = &symbols[i]
	}

	textSection := disassembler.f.Section(".text")
	if textSection == nil {
		log.Fatal("No text section")
	}

	textData, err := textSection.Data()
	if err != nil {
		log.Fatal(err)
	}

symLoop:
	for _, sym := range symbols {

		logIfVerbose("SYM %s\t%x\t%s\n", sym.Name, sym.Value, sym.Section.String())

		// Only care about function symbols
		if sym.Info != byte(2) && sym.Info != byte(18) { // why tf is info==18 functions in go bins?
			logIfVerbose("\tNOT FUNCTION: %d\n", sym.Info)
			continue symLoop
		}

		// Don't want no empty symbols!
		if sym.Size == 0 {
			logIfVerbose("\tSIZE 0\n")
			continue symLoop
		}

		symbolLocation := sym.Value - textSection.Addr
		symbolData := []byte{}

		// Loop through textData starting at symbolLocation for symbol.Size bytes
		for _, b := range textData[symbolLocation : symbolLocation+sym.Size] {
			symbolData = append(symbolData, b)
		}

		// Dissasemble the symbol
		symbolInstrucitons, err := disassembler.e.Disasm(symbolData, sym.Value, 0x0)
		if err != nil {
			logIfVerbose("ERROR DISASSEMBLING: %s\n", err.Error())
			continue symLoop
		}

		fmt.Printf("\n\nSYMBOL %s\n", sym.Name)
		for _, ins := range symbolInstrucitons {
			printInstruction(ins, symMap)
		}
	}
}

func printInstruction(ins gapstone.Instruction, symbols map[uint64]*elf.Symbol) {

	fmt.Printf("0x%x:\t%s\t\t%s", ins.Address, ins.Mnemonic, ins.OpStr)
	defer fmt.Printf("\n")

	// Annotate calls
	if ins.Mnemonic == "call" {
		callAddrWithoutHex := strings.TrimPrefix(ins.OpStr, "0x")
		symAddress, err := strconv.ParseUint(callAddrWithoutHex, 16, 64)
		if err != nil {
			return
		}
		if symAddress == 0 || symbols[symAddress] == nil {
			return
		}
		fmt.Printf("\t\t\t# %s", symbols[symAddress].Name)
	}
}

// logIfVerbose writes a formated string to stderr if `globalVerbose` is set to true
func logIfVerbose(format string, values ...interface{}) {
	if globalVerbose {
		message := fmt.Sprintf(format, values...)
		coloredMessageFunc := color.New(color.FgCyan).SprintfFunc()
		fullMessage := coloredMessageFunc("%s", message)
		fmt.Fprintf(os.Stderr, "%s", fullMessage)
	}
}
