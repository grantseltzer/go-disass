package main

import (
	"debug/elf"
	"errors"
	"fmt"

	"github.com/bnagy/gapstone"
)

var (
	// ErrSymbolNotFound is returned if a symbol can't be found by name
	ErrSymbolNotFound = errors.New("symbol not found")
)

// Disassembler wraps elf.File objects and the dissasembler engine
type Disassembler struct {
	f *elf.File
	e *gapstone.Engine
}

// NewDisassembler returns a pointer to a new Disassembler
func NewDisassembler() *Disassembler {
	return &Disassembler{}
}

// Open will load an ELF pointed at by 'path' into memory
func (d *Disassembler) Open(path string) error {

	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("error while opening file %s: %+s", path, err.Error())
	}

	// Close previously loaded file if it exists
	if d.f != nil {
		d.f.Close()
	}

	d.f = f

	return nil
}

// StartEngineX86_64 init's the Disassembler with a new x86_64 capstone engine
func (d *Disassembler) StartEngineX86_64() error {
	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_64,
	)
	if err != nil {
		return err
	}
	d.e = &engine
	return nil
}
