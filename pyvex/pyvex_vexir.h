#ifndef __VEXIR_H
#define __VEXIR_H

#include <libvex.h>

// Some info required for translation
extern VexArchInfo         vai;
extern VexGuestExtents     vge;
extern VexTranslateArgs    vta;
extern VexTranslateResult  vtr;
extern VexAbiInfo	   vbi;
extern VexControl	   vc;

//
// Initializes VEX. This function must be called before vex_insn
// can be used. 
//
void vex_init(void);

//
// Translates assembly instructions and blocks into VEX
IRSB *vex_instruction(VexArch guest, unsigned char *insn_start, unsigned int insn_addr, int max_insns);
IRSB *vex_block_bytes(VexArch guest, unsigned char *instructions, unsigned long long block_addr, unsigned int num_bytes);
IRSB *vex_block_inst(VexArch guest, unsigned char *instructions, unsigned long long block_addr, unsigned int num_inst);
int vex_count_instructions(VexArch guest, unsigned char *instructions, unsigned long long block_addr, unsigned int num_bytes);

#endif
