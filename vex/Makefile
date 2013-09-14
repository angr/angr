VGPREFIX=$(HOME)/valgrind/inst
CFLAGS=-I$(VGPREFIX)/include/valgrind --std=c99 -g -fPIC
LDFLAGS=-L$(VGPREFIX)/lib/valgrind -lvex-amd64-linux -largtable2
EXE=angr_vex
CC=gcc

all: $(EXE) $(EXE).a

$(EXE): angr_common.o angr_vex.o angr_vexir.o
	gcc $+ $(LDFLAGS) -o $(EXE)

$(EXE).a: angr_common.o angr_vexir.o
	ar rcs $(EXE).a $+

clean:
	rm -f $(EXE) $(EXE).a *.o
