all: sym-amd64 sym-ppc32 sym-mips32

sym-arm: sym.c
	arm-linux-gnueabi-gcc -o arm/sym sym.c -ldl

sym-ppc32: sym.c
	powerpc-linux-gnu-gcc -o ppc/sym sym.c -ldl

sym-amd64: sym.c
	gcc -o x86_64/sym sym.c -ldl

sym-mips32: sym.c
	mips-linux-gnu-gcc -o mips/sym sym.c -ldl

clean:
	rm -f */sym
