UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_ANGR_NATIVE=angr_native.dylib
endif
ifeq ($(UNAME), Linux)
	LIB_ANGR_NATIVE=angr_native.so
endif

CC := gcc
C++C := g++
CFLAGS := -I "${UNICORN_INCLUDE_PATH}" -I "${PYVEX_INCLUDE_PATH}" \
	-L "${UNICORN_LIB_PATH}" -L "${PYVEX_LIB_PATH}" \
	-O3 -fPIC -std=c++11
ifneq ($(DEBUG), )
	CFLAGS := $(CFLAGS) -O0 -g
endif

OBJS := log.o
LIBS := -lunicorn -lpyvex

all: ${LIB_ANGR_NATIVE}

log.o: log.c log.h
	${CC} -fPIC -c -O3 -o $@ $<

${LIB_ANGR_NATIVE}: ${OBJS} sim_unicorn.cpp
	${C++C} ${CFLAGS} -shared -o $@ $^ ${LIBS}

clean:
	rm -f "${LIB_ANGR_NATIVE}" *.o arch/*.o
