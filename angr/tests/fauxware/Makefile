all: fauxware-amd64 fauxware-ppc32 fauxware-arm fauxware-x86 fauxware-mips
	rm -f *.??? *.idb

fauxware-arm: fauxware.c
	arm-linux-gnueabi-gcc -o arm32l/fauxware fauxware.c

fauxware-ppc32: fauxware.c
	powerpc-linux-gnu-gcc -o ppc32/fauxware fauxware.c

fauxware-x86: fauxware.c
	gcc -m32 -o x86/fauxware fauxware.c

fauxware-amd64: fauxware.c
	gcc -o amd64/fauxware fauxware.c -fno-stack-protector

fauxware-mips: fauxware.c
	mips-linux-gnu-gcc -o mips32l/fauxware fauxware.c -fno-stack-protector


clean:
	rm fauxware-*
	rm -f *.??? *.idb
