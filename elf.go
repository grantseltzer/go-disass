package main

import (
	"debug/elf"
	"strings"
)

// getExecutableSections will return a slice of elf.Section's
// that have the SHF_EXECINSTR flag
func getExecutableSections(path string) ([]*elf.Section, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	executableSections := []*elf.Section{}
	for _, section := range f.Sections {
		if strings.Contains(section.Flags.String(), "SHF_EXECINSTR") {
			executableSections = append(executableSections, section)
		}
	}

	return executableSections, nil
}
