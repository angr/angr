UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_ANGR_NATIVE=angr_native.dylib
endif
ifeq ($(UNAME), FreeBSD)
	LIB_ANGR_NATIVE=angr_native.so
endif
ifeq ($(UNAME), Linux)
	LIB_ANGR_NATIVE=angr_native.so
endif
ifeq ($(UNAME), OpenBSD)
	LIB_ANGR_NATIVE=angr_native.so
endif

CC ?= gcc
CXX ?= g++
CFLAGS ?= -O3
CFLAGS += -fPIC
CXXFLAGS ?= -O3
CXXFLAGS += -fPIC -std=c++11
ifneq ($(DEBUG), )
	CFLAGS += -O0 -g
	CXXFLAGS += -O0 -g
endif
CPPFLAGS += -I vendor -I "${PYVEX_INCLUDE_PATH}"
CFLAGS += -I vendor
LDFLAGS += -L "${PYVEX_LIB_PATH}" -shared

OBJS := log.o unicorn_dynamic.o
LDLIBS := -lpyvex
ifeq ($(UNAME), Darwin)
	LDFLAGS += -Wl,-rpath,"${PYVEX_LIB_PATH}"
endif

ifeq ($(UNAME), Linux)
	LDLIBS += -ldl
endif

all: ${LIB_ANGR_NATIVE}

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

${LIB_ANGR_NATIVE}: ${OBJS} sim_unicorn.cpp
	${CXX} ${CXXFLAGS} ${CPPFLAGS} -o $@ $^ ${LDLIBS} ${LDFLAGS}

clean:
	rm -f "${LIB_ANGR_NATIVE}" *.o arch/*.o
