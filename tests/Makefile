
# Flags
cflags=-Wall -fstack-protector
cflags_ppc64=-I/cross/ppc/usr/include/powerpc-linux-gnu/

# All the compilers
cc_x64=x86_64-linux-gnu-gcc $(cflags)
cc_mips=mips-linux-gnu-gcc $(cflags)
cc_mipsel=mipsel-linux-gnu-gcc $(cflags)
cc_ppc=powerpc-linux-gnu-gcc $(cflags)
cc_ppc64=powerpc-linux-gnu-gcc -m64 $(cflags)
cc_armel=arm-linux-gnueabi-gcc $(cflags)
cc_armhf=arm-linux-gnueabihf-gcc $(cflags)
cc_x86= gcc -m32 $(cflags)

# All the C source files
files:=$(wildcard src/*.c)

# And corresponding objects (same name without .c)
obj := $(files:.c=)
target := $(subst src/, , $(obj))

all: $(target)

%: src/%.c
	mkdir -p build/i386 build/x86_64
	$(cc_x86) $^ -o build/i386/$@
	$(cc_x64) $^ -o build/x86_64/$@

ifneq (, $(shell $(cc_ppc) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir build/ppc
	$(cc_ppc) $^ -o build/ppc/$@
endif

ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir -p build/ppc_64
	$(cc_ppc64) $^ -o build/ppc64/$@
endif

ifneq (,$(shell which $(cc_armhf)))
	mkdir -p build/armhf
	$(cc_armhf) $^ -o build/armhf/$@
endif

ifneq (,$(shell which $(cc_armel)))
	mkdir -p build/armel
	$(cc_armel) $^ -o build/armel/$@
endif

ifneq (,$(shell which $(cc_mips)))
	mkdir -p build/mips
	$(cc_mips) $^ -o build/mips/$@
endif

ifneq (,$(shell which $(cc_mipsel)))
	mkdir -p build/mipsel
	$(cc_mipsel) $^ -o build/mipsel/$@
endif


clean: 
	rm -rf build
