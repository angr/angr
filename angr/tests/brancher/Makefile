all: brancher-amd64 brancher-ppc32 brancher-arm
	rm -f *.??? *.idb

brancher-arm: brancher.c
	arm-linux-gnueabi-gcc -o brancher-ppc32 brancher.c

brancher-ppc32: brancher.c
	powerpc-linux-gnu-gcc -o brancher-ppc32 brancher.c

brancher-amd64: brancher.c
	gcc -o brancher-amd64 brancher.c

clean:
	rm brancher-*
	rm -f *.??? *.idb
