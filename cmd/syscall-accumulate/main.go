package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

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
		symbolInstructions, err := disassembler.e.Disasm(symbolData, sym.Value, 0x0)
		if err != nil {
			logIfVerbose("ERROR DISASSEMBLING: %s\n", err.Error())
			continue symLoop
		}

		var previousInstruction = symbolInstructions[0]
		foundSyscallNumbers := []int{}

		for _, ins := range symbolInstructions {

			if ins.Mnemonic == "syscall" && previousInstruction.Mnemonic == "mov" {
				opStrings := []string{}
				opString := ""

				if strings.Contains(previousInstruction.OpStr, "0x") {
					opStrings = strings.Split(previousInstruction.OpStr, "0x")
					opString = opStrings[1]
				} else {
					opStrings = strings.Split(previousInstruction.OpStr, " ")
					opString = opStrings[1]
				}

				i, err := strconv.ParseInt(opString, 16, 0)
				if err == nil {
					foundSyscallNumbers = append(foundSyscallNumbers, int(i))
				} else {
					fmt.Printf("error: %s \n", opString)
				}
			}

			previousInstruction = ins
		}

		for _, syscallNumber := range foundSyscallNumbers {
			name, err := ausyscall(syscallNumber)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", name)
		}

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

func ausyscall(syscallNumber int) ([]byte, error) {

	cmd := exec.Command("/usr/bin/ausyscall", fmt.Sprintf("%d", syscallNumber))
	var outb bytes.Buffer
	cmd.Stdout = &outb

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return outb.Bytes(), nil
}
