# pysex

PySEX is a Symbolic EXecution engine for VEX IR. It reimplements many of the ideas behind Mayhem.

## Requirements

PySEX requires PyVEX to be installed.

## Use

You can use pysex pretty easily! Give it some bytes to translate, the base (in actual memory) where those bytes would be loaded, and the entry point (relative offset into the bytes) where to start the execution.

	symbolic_blocks = pysex.translate_bytes(bytes="\x5d\xc3", entry=0, base=0)

Awesome stuff!

## Next steps

- Complete the symbolic memory stuff.

## Bugs

- None! (haha)
