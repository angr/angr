all: sym-amd64 sym-ppc32 sym-arm

sym-arm: sym.c
	arm-linux-gnueabi-gcc -o arm/sym sym.c -ldl

sym-ppc32: sym.c
	powerpc-linux-gnu-gcc -o ppc/sym sym.c -ldl

sym-amd64: sym.c
	gcc -o x86_64/sym sym.c -ldl

clean:
	rm -f */sym
