UNICORN_PATH?=../unicorn

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIB_SIM_UNICORN=sim_unicorn.dylib
endif
ifeq ($(UNAME), Linux)
	LIB_SIM_UNICORN=sim_unicorn.so
endif

${LIB_SIM_UNICORN}: sim_unicorn.cpp ${UNICORN_PATH}/libunicorn.so
	g++ -g -std=c++11 -shared -fPIC -I${UNICORN_PATH}/include/unicorn -o ${LIB_SIM_UNICORN} $^

clean:
	rm -f ${LIB_SIM_UNICORN}
