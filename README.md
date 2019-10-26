# go-disassembler-tools

This repository contains:

1) disasm - a tool that disassembles x86_64 ELF binaries and prints to stdout

2) rop-tool - a tool that finds locations of rop-gadgets in a x86_64 ELF binary and prints to stdout

3) syscall-accumulate - a tool that finds all direct references to syscalls in a x86_64 ELF binary and prints the list to stdout.

See associated blog post [here](https://www.grant.pizza/blog/dissecting-go-binaries)

### Dependencies

Requires `capstone` and `capstone-devel`

Syscall-accumulate requires `ausyscall`

(Check your distro listings)
