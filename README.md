# angr

A tool to get you VEXed!

## Dependencies

- idalink (http://github.com/zardus/idalink)
- pyvex (http://github.com/zardus/pyvex)

## Usage

You can use angr as follows:

	import angr
	b = angr.Binary("/path/to/binary")
	b.load_all_functions()

	for f in b.functions.values():
		print f.vex_blocks

Something like that.

## Resources

Some interesting resources.

- http://osll.spb.ru/projects/llvm
- https://github.com/bitblaze-fuzzball/fuzzball/blob/master/libasmir/src/vex/Notes
