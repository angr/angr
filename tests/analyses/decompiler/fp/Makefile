CC := gcc
SRC := fp_basic.c

# i386 x87 (all FP via x87 stack)
I386_FLAGS := -m32 -mfpmath=387 -fno-pic -no-pie

# amd64 x87 (forced x87 via -mfpmath=387)
AMD64_X87_FLAGS := -mlong-double-80 -mfpmath=387 -mno-sse2 -no-pie

# amd64 default (SSE FP)
AMD64_SSE_FLAGS := -no-pie

BINS := \
	fp_basic_i386_O0 \
	fp_basic_i386_O1 \
	fp_basic_amd64_O0 \
	fp_basic_amd64_O1 \
	fp_basic_amd64_default_O0 \
	fp_basic_amd64_default_O1

# Hand-crafted assembly (.o relocatable objects)
ASM_BINS := \
	four_doubles_i386.o \
	ftop_conflict_i386.o \
	slot_reuse_amd64.o \
	slot_reuse_i386.o

all: $(BINS) $(ASM_BINS)

fp_basic_i386_O0: $(SRC)
	$(CC) -O0 $(I386_FLAGS) -o $@ $<

fp_basic_i386_O1: $(SRC)
	$(CC) -O1 $(I386_FLAGS) -o $@ $<

fp_basic_amd64_O0: $(SRC)
	$(CC) -O0 $(AMD64_X87_FLAGS) -o $@ $<

fp_basic_amd64_O1: $(SRC)
	$(CC) -O1 $(AMD64_X87_FLAGS) -o $@ $<

fp_basic_amd64_default_O0: $(SRC)
	$(CC) -O0 $(AMD64_SSE_FLAGS) -o $@ $<

fp_basic_amd64_default_O1: $(SRC)
	$(CC) -O1 $(AMD64_SSE_FLAGS) -o $@ $<

four_doubles_i386.o: four_doubles_i386.s
	nasm -f elf32 -o $@ $<

ftop_conflict_i386.o: ftop_conflict_i386.s
	nasm -f elf32 -o $@ $<

slot_reuse_amd64.o: slot_reuse_amd64.s
	nasm -f elf64 -o $@ $<

slot_reuse_i386.o: slot_reuse_i386.s
	nasm -f elf32 -o $@ $<

clean:
	rm -f $(BINS) $(ASM_BINS)

.PHONY: all clean
