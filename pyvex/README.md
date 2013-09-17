# pyvex

A python interface into Valgrind's VEX IR!

## Build

For now, pyvex is tricky to build. First, valgrind needs to be compiled with fPIC:

	mkdir ~/valgrind
	cd ~/valgrind
	wget http://valgrind.org/downloads/valgrind-3.8.1.tar.bz2
	tar xvfj valgrind-3.8.1.tar.bz2
	cd valgrind-3.8.1
	CFLAGS=-fPIC ./configure --prefix=$HOME/valgrind/inst
	make
	make install

Great! Now you can build pyvex. First, you need to build the stuff in the angr/vex directory. Then, you can build pyvex!

	python setup.py build

Sweet!

## Use

You can use pyvex pretty easily. For now, it only supports translation and pretty printing:

	import pyvex
	irsb = pyvex.IRSB(bytes="\x55\xc3") # translates "push ebp; ret" to VEX IR
	irsb.pp() # prints the VEX IR

Awesome stuff!

## Bugs

- pretty-printing an emptyIRSB segfaults
- there is no memory management. VEX is kind of weird with this, so care will have to be taken...
- converting from string to tag is currently very slow (a hastily written consecutive bunch of strcmps)
