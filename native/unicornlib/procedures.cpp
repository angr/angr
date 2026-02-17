#define __STDC_FORMAT_MACROS 1
#define NOMINMAX
#ifdef _MSC_VER
// get this out of the way... it's requried deep within unicorn
#include <windows.h>
#endif

#include <cstdint>
#include <cstring>

#include "sim_unicorn.hpp"

// this is a shitshow; will need some notion of "calling convention"
uint64_t arg(State *state, int idx) {
    switch (state->arch) {
        case UC_ARCH_X86:
            if (state->unicorn_mode == UC_MODE_32) {
                uint32_t esp;
                uc_reg_read(state->uc, UC_X86_REG_ESP, &esp);
                uint32_t res;
                uc_mem_read(state->uc, esp + (1 + idx) * 4, &res, 4);
                return res;
            } else {
                uint64_t rsp;
                uc_reg_read(state->uc, UC_X86_REG_RSP, &rsp);
                uint64_t res;
                uc_mem_read(state->uc, rsp + (1 + idx) * 8, &res, 8);
                return res;
            }
    }
    return 0;
}

void ret(State *state, uint64_t val) {
    switch (state->arch) {
        case UC_ARCH_X86:
            if (state->unicorn_mode == UC_MODE_32) {
                uint32_t esp;
                uc_reg_read(state->uc, UC_X86_REG_ESP, &esp);
                uint32_t ret_addr;
                uc_mem_read(state->uc, esp, &ret_addr, 4);
                esp += 4;
                uc_reg_write(state->uc, UC_X86_REG_ESP, &esp);
                uc_reg_write(state->uc, UC_X86_REG_EIP, &ret_addr);
                uc_reg_write(state->uc, UC_X86_REG_EAX, &val);
                break;
            } else {
                uint64_t rsp;
                uc_reg_read(state->uc, UC_X86_REG_RSP, &rsp);
                uint64_t ret_addr;
                uc_mem_read(state->uc, rsp, &ret_addr, 8);
                rsp += 8;
                uc_reg_write(state->uc, UC_X86_REG_RSP, &rsp);
                uc_reg_write(state->uc, UC_X86_REG_RIP, &ret_addr);
                uc_reg_write(state->uc, UC_X86_REG_RAX, &val);
                break;
            }
    }
}

void ucproc_malloc(State *state) {
    uint64_t size = arg(state, 0);
    do {
        size++;
    } while (size % 0x10);
    uint64_t result = state->heap_base;
    state->heap_base += size;
    ret(state, result);
}

void ucproc_memset(State *state) {
    uint64_t dst = arg(state, 0);
    uint64_t src = arg(state, 1);
    uint64_t size = arg(state, 2);
    char *bigbuf = (char*)malloc(0x1000);
    memset(bigbuf, src, 0x1000);
    state->handle_write(dst, size, true, false);
    if (state->stopped) {
    	free(bigbuf);
    	return;
    }
    for (uint64_t i = 0; i < size; i += 0x1000) {
        uint64_t chunksize = size - i;
        if (chunksize > 0x1000) {
            chunksize = 0x1000;
        }
        uc_mem_write(state->uc, dst, bigbuf, chunksize);
    }
    free(bigbuf);
    ret(state, dst);
}
