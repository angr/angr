#define NEED_CPU_H
#include "qemu-common.h"

#include "uc_priv.h"

#include "../log.h"

static void regcpy(void *dest, void *src) {
	memcpy(dest, src, offsetof(CPUMIPSState, tlb_table));
}

extern void mips_reg_update(uc_engine *uc, uint8_t *buf, int save) {
	if (save)
		regcpy(buf, uc->current_cpu->env_ptr);
	else
		regcpy(uc->current_cpu->env_ptr, buf);

	LOG_D("%s: $pc = %#x\n", save ? "save" : "load", ((CPUMIPSState *)buf)->active_tc.PC);
};

