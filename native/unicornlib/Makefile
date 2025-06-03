UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_UNICORNLIB=unicornlib.dylib
endif
ifeq ($(UNAME), FreeBSD)
	LIB_UNICORNLIB=unicornlib.so
endif
ifeq ($(UNAME), Linux)
	LIB_UNICORNLIB=unicornlib.so
endif
ifeq ($(UNAME), OpenBSD)
	LIB_UNICORNLIB=unicornlib.so
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

all: ${LIB_UNICORNLIB}

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

${LIB_UNICORNLIB}: ${OBJS} sim_unicorn.cpp
	${CXX} ${CXXFLAGS} ${CPPFLAGS} -o $@ $^ ${LDLIBS} ${LDFLAGS}

clean:
	rm -f "${LIB_UNICORNLIB}" *.o arch/*.o
