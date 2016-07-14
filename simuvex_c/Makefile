UNICORN_PATH?=../unicorn
VEX_PATH?=../../vex
PYVEX_PATH?=../../pyvex/pyvex_c
QEMU_PATH := ${UNICORN_PATH}/qemu

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_SIM_UNICORN=sim_unicorn.dylib
endif
ifeq ($(UNAME), Linux)
	LIB_SIM_UNICORN=sim_unicorn.so
endif

CC := gcc
CFLAGS := -I ${UNICORN_PATH}/include -I ${UNICORN_PATH}/include/unicorn -I ${QEMU_PATH} \
	  -I ${QEMU_PATH}/include -I ${VEX_PATH}/pub -I ${PYVEX_PATH} `pkg-config --cflags glib-2.0` \
          -O3
LFLAGS := -L ${UNICORN_PATH}
LIBS := -lglib-2.0 -lunicorn
OBJS := log.o arch/x86.o arch/mips.o

all: ${LIB_SIM_UNICORN}

log.o: log.c log.h
	${CC} -fPIC -c -O3 -o $@ $<

arch/x86.o: arch/x86.c
	${CC} -fPIC ${CFLAGS} -I ${QEMU_PATH}/target-i386 -I ${QEMU_PATH}/x86_64-softmmu -o $@ -c $<

arch/mips.o: arch/mips.c
	${CC} -fPIC ${CFLAGS} -I ${QEMU_PATH}/target-mips -I ${QEMU_PATH}/mips-softmmu -o $@ -c $<

${LIB_SIM_UNICORN}: sim_unicorn.cpp ${OBJS}
	g++ -g -std=c++11 -shared -fPIC ${CFLAGS} -o $@ $^ ${LIBS}

clean:
	rm -f ${LIB_SIM_UNICORN} *.o arch/*.o
