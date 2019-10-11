default: disasm rop-tool syscall

disasm:
	go build -o bin/go-disassembler ./cmd/disasm

rop-tool:
	go build -o bin/rop-tool ./cmd/rop-tool

syscall:
	go build -o bin/syscallac ./cmd/syscall-accumulate

clean:
	rm ./bin/*

help:
	@echo  "•‿• <( whats up )" 
