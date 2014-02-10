all: fauxware-amd64 fauxware-ppc32 fauxware-arm
	rm -f *.??? *.idb

fauxware-arm: fauxware.c
	arm-linux-gnueabi-gcc -o fauxware fauxware.c

fauxware-ppc32: fauxware.c
	powerpc-linux-gnu-gcc -o fauxware fauxware.c

fauxware-amd64: fauxware.c
	gcc -o fauxware fauxware.c -fno-stack-protector

clean:
	rm fauxware-*
	rm -f *.??? *.idb
