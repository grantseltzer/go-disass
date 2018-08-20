default: disasm rop-tool

disasm:
	go build -o bin/go-disassembler ./cmd/disasm

rop-tool:
	go build -o bin/rop-tool ./cmd/rop-tool

clean:
	rm ./bin/*

help:
	@echo  "•‿• <( whats up )" 
