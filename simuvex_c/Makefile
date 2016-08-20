UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_SIM_UNICORN=sim_unicorn.dylib
endif
ifeq ($(UNAME), Linux)
	LIB_SIM_UNICORN=sim_unicorn.so
endif

CC := gcc
C++C := g++
CFLAGS := -I ${UNICORN_INCLUDE_PATH} -I ${PYVEX_INCLUDE_PATH} \
	-L ${UNICORN_LIB_PATH} -L ${PYVEX_LIB_PATH} \
	`pkg-config --cflags glib-2.0` -O3 -fPIC -std=c++11

OBJS := log.o
LIBS := -lglib-2.0 -lunicorn -lpyvex

all: ${LIB_SIM_UNICORN}

log.o: log.c log.h
	${CC} -fPIC -c -O3 -o $@ $<

${LIB_SIM_UNICORN}: ${OBJS} sim_unicorn.cpp
	${C++C} ${CFLAGS} -shared -o $@ $^ ${LIBS}

clean:
	rm -f ${LIB_SIM_UNICORN} *.o arch/*.o
