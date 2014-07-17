all: fauxware-amd64 fauxware-ppc32 fauxware-arm fauxware-x86 fauxware-mips
	rm -f *.??? *.idb

fauxware-arm: fauxware.c
	arm-linux-gnueabi-gcc -o fauxware-arm fauxware.c

fauxware-ppc32: fauxware.c
	powerpc-linux-gnu-gcc -o fauxware-ppc32 fauxware.c

fauxware-x86: fauxware.c
	gcc -m32 -o fauxware-x86 fauxware.c

fauxware-amd64: fauxware.c
	gcc -o fauxware-amd64 fauxware.c -fno-stack-protector

fauxware-mips: fauxware.c
	mips-linux-gnu-gcc -o fauxware-mips fauxware.c -fno-stack-protector


clean:
	rm fauxware-*
	rm -f *.??? *.idb
