#define NEED_CPU_H
#include "qemu-common.h"

#include "uc_priv.h"

#include "../log.h"

static void regcpy(void *dest, void *src) {
	memcpy(dest, src, (size_t)&(((CPUX86State *)0)->tlb_table));
}

extern void x86_reg_update(uc_engine *uc, uint8_t *buf, int save) {
	if (save)
		regcpy(buf, uc->current_cpu->env_ptr);
	else
		regcpy(uc->current_cpu->env_ptr, buf);

	LOG_D("%s: $pc = %#lx\n", save ? "save" : "load", ((CPUX86State *)buf)->eip);
};

