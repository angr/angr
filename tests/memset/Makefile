all: memset-amd64 memset-ppc32 memset-arm
	rm -f *.??? *.idb

memset-arm: memset.c
	arm-linux-gnueabi-gcc -fno-inline-small-functions -o memset-arm memset.c

memset-ppc32: memset.c
	powerpc-linux-gnu-gcc -fno-inline-small-functions -o memset-ppc32 memset.c

memset-amd64: memset.c
	gcc -fno-inline-small-functions -o memset-amd64 memset.c

clean:
	rm memset-*
	rm -f *.??? *.idb
