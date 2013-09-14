# angr

A tool to get you VEXed!

## Running

You, too, can run it!

    sudo apt-get install valgrind libargtable2-dev
    # Modify the include and lib path inside Makefile accordingly ;)
	make
	./angr -v -b ../v/a.out -f 0x4b4 -m 0x4004b4 -n 25 -i 9

This will read 25 bytes from the ../v/a.out file at offset 0x4b4, tell VEX that they should be at 0x4004b4, and convert 9 instructions starting from there to VEX. The -i argument can be ommitted, in which case it'll detect the number of instructions at the cost of having to convert it to VEX instruction-by-instruction at first.

## Resources

Some interesting resources.

- http://osll.spb.ru/projects/llvm
- https://github.com/bitblaze-fuzzball/fuzzball/blob/master/libasmir/src/vex/Notes
