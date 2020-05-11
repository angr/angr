UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_ANGR_NATIVE=angr_native.dylib
endif
ifeq ($(UNAME), Linux)
	LIB_ANGR_NATIVE=angr_native.so
endif

CC := gcc
CXX := g++
CXXFLAGS := -I "${UNICORN_INCLUDE_PATH}" -I "${PYVEX_INCLUDE_PATH}" \
	-L "${UNICORN_LIB_PATH}" -L "${PYVEX_LIB_PATH}" \
	-O3 -fPIC -std=c++11
ifneq ($(DEBUG), )
	CXXFLAGS := $(CXXFLAGS) -O0 -g
endif

OBJS := log.o
LDLIBS := -lunicorn -lpyvex
ifeq ($(UNAME), Darwin)
	LDFLAGS := -Wl,-rpath,"${UNICORN_LIB_PATH}",-rpath,"${PYVEX_LIB_PATH}"
endif

all: ${LIB_ANGR_NATIVE}

log.o: log.c log.h
	${CC} -fPIC -c -O3 -o $@ $<

${LIB_ANGR_NATIVE}: ${OBJS} sim_unicorn.cpp
	${CXX} ${CXXFLAGS} -shared -o $@ $^ ${LDLIBS} ${LDFLAGS}

clean:
	rm -f "${LIB_ANGR_NATIVE}" *.o arch/*.o
