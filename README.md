# simuvex

SimuVEX is a simulation engine for VEX IR. It reimplements many of the ideas behind Mayhem.

## Requirements

SimuVEX has the following requirements:

- pyvex
- z3

## Use

You can use SimuVEX pretty easily! Give it some bytes to translate, the base (in actual memory) where those bytes would be loaded, and the entry point (relative offset into the bytes) where to start the execution.

	symbolic_blocks = simuvex.translate_bytes(bytes="\x5d\xc3", entry=0, base=0)

Awesome stuff!

## Supporting a new architecture

These are the steps required to support a new VEX arch:

1. Implement the ccalls that VEX uses for that architecture (for example, the condition flag crap). These are located in s\_ccall.py.
2. Implement a SimARCH class for it in s\_arch.py. This is for stuff like return emulation, and the bit width of the architecture.

## Next steps

## Bugs

- None! (haha)
