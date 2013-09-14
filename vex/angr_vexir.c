/*
This is shamelessly ripped from Vine, because those guys suck.
Vine is Copyright (C) 2006-2009, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU GPL,
version 2 or later, but it is made available WITHOUT ANY WARRANTY.
See the top-level README file for more details.

For more information about Vine and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

//======================================================================
//
// This file provides the interface to VEX that allows block by block
// translation from binary to VEX IR.
//
//======================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "angr_vexir.h"
#include "angr_common.h"
#include "libvex.h"

#define AMD64
extern VexControl vex_control;

//======================================================================
//
// Globals
//
//======================================================================

// Some info required for translation
VexArchInfo         vai;
VexGuestExtents     vge;
VexTranslateArgs    vta;
VexTranslateResult  vtr;
VexAbiInfo	    vbi;
VexControl vc;

// Define a temp buffer to hold the vexed bytes
// Not needed with patched VEX
#ifndef AMD64
#define             TMPBUF_SIZE 2000
UChar               tmpbuf[TMPBUF_SIZE];
Int                 tmpbuf_used;
#endif

// Global for saving the intermediate results of translation from
// within the callback (instrument1)
IRSB *irbb_current = NULL;

//======================================================================
//
// Functions needed for the VEX translation
//
//======================================================================

__attribute((noreturn)) void failure_exit( void )
{
	printf("SHIIIIIT\n");
	exit(1);
}

void log_bytes( HChar* bytes, Int nbytes )
{
	Int i;
	for (i = 0; i < nbytes - 3; i += 4)
		printf("%c%c%c%c", bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
	for (; i < nbytes; i++)
		printf("%c", bytes[i]);
}

Bool chase_into_ok( void *closureV, Addr64 addr64 )
{
	return False;
}

// TODO: figure out what this is for
UInt needs_self_check(void *callback_opaque, VexGuestExtents *guest_extents)
{
	return 0;
}

void *dispatch(void)
{
	return NULL;
}

//----------------------------------------------------------------------
// This is where we copy out the IRSB
//----------------------------------------------------------------------
IRSB *instrument1(  void *callback_opaque,
                    IRSB *irbb,
                    VexGuestLayout *vgl,
                    VexGuestExtents *vge,
                    IRType gWordTy,
                    IRType hWordTy )
{

	assert(irbb);

	//irbb_current = (IRSB *)vx_dopyIRSB(irbb);
	irbb_current = deepCopyIRSB(irbb);

	if (debug_on) ppIRSB(irbb);
	return irbb;
}


//----------------------------------------------------------------------
// Initializes VEX
// It must be called before using VEX for translation to Valgrind IR
//----------------------------------------------------------------------
void vex_init()
{
	static int initialized = 0;
	debug("Initializing VEX.\n");

	if (initialized)
	{
		debug("VEX already initialized.\n");
		return;
	}
	initialized = 1;

	//
	// Initialize VEX
	//
	vc.iropt_verbosity              = 0;
	vc.iropt_level                  = 0;    // No optimization by default
	//vc.iropt_level                  = 2;
	//vc.iropt_precise_memory_exns    = False;
	vc.iropt_unroll_thresh          = 0;
	vc.guest_max_insns              = 1;    // By default, we vex 1 instruction at a time
	vc.guest_chase_thresh           = 0;

	debug("Calling LibVEX_Init()....\n");
	LibVEX_Init(&failure_exit,
	            &log_bytes,
	            0,              // Debug level
	            False,          // Valgrind support
	            &vc );
	debug("LibVEX_Init() done....\n");

	LibVEX_default_VexArchInfo(&vai);
	LibVEX_default_VexAbiInfo(&vbi);
	vbi.guest_stack_redzone_size = 128;

	//------------------------------------
	// options for instruction translation

	//
	// Architecture info
	//
	vta.arch_guest          = VexArch_INVALID; // to be assigned later
	//vta.arch_guest          = VexArchARM;
	//vta.arch_guest          = VexArchX86;               // Source arch
	vta.archinfo_guest      = vai;
	// FIXME: detect this one automatically
#ifdef AMD64
	vta.arch_host           = VexArchAMD64;
#else
	vta.arch_host           = VexArchX86;               // Target arch
#endif
	vta.archinfo_host       = vai;
	vta.abiinfo_both	= vbi;

	//
	// The actual stuff to vex
	//
	vta.guest_bytes         = NULL;             // Set in vex_insts
	vta.guest_bytes_addr    = 0;                // Set in vex_insts

	//
	// callbacks
	//
	vta.callback_opaque     = NULL;             // Used by chase_into_ok, but never actually called
	vta.chase_into_ok       = chase_into_ok;    // Always returns false
	vta.preamble_function   = NULL;
	vta.instrument1         = instrument1;      // Callback we defined to help us save the IR
	vta.instrument2         = NULL;
	vta.finaltidy		= NULL;
	vta.needs_self_check	= needs_self_check;	

	#if 0
		vta.dispatch_assisted	= (void *)dispatch; // Not used
		vta.dispatch_unassisted	= (void *)dispatch; // Not used
	#else
		vta.disp_cp_chain_me_to_slowEP = (void *)dispatch; // Not used
		vta.disp_cp_chain_me_to_fastEP = (void *)dispatch; // Not used
		vta.disp_cp_xindir = (void *)dispatch; // Not used
		vta.disp_cp_xassisted = (void *)dispatch; // Not used
	#endif

	vta.guest_extents       = &vge;
#ifdef AMD64
	vta.host_bytes          = NULL;           // Buffer for storing the output binary
	vta.host_bytes_size     = 0;
	vta.host_bytes_used     = NULL;
#else
	vta.host_bytes          = tmpbuf;           // Buffer for storing the output binary
	vta.host_bytes_size     = TMPBUF_SIZE;
	vta.host_bytes_used     = &tmpbuf_used;
#endif
	// doesn't exist? vta.do_self_check       = False;
	vta.traceflags          = 0;                // Debug verbosity
	//vta.traceflags          = -1;                // Debug verbosity
}

//----------------------------------------------------------------------
// Translate 1 instruction to VEX IR.
//----------------------------------------------------------------------
IRSB *vex_inst(VexArch guest, unsigned char *insn_start, unsigned int insn_addr, int max_insns)
{
	vta.arch_guest = guest;
	vta.guest_bytes         = (UChar *)(insn_start);  // Ptr to actual bytes of start of instruction
	vta.guest_bytes_addr    = (Addr64)(insn_addr);

	debug("Setting VEX max instructions...\n");
	debug("... old: %d\n", vex_control.guest_max_insns);
	vex_control.guest_max_insns = max_insns;    // By default, we vex 1 instruction at a time
	debug("... new: %d\n", vex_control.guest_max_insns);

	// Do the actual translation
	vtr = LibVEX_Translate(&vta);

	debug("Translated!\n");

	assert(irbb_current);
	return irbb_current;
}

vexed_block *vex_bytes(VexArch guest, unsigned char *instructions, unsigned int block_addr, unsigned int num_bytes)
{
	vexed_block *vb = malloc(sizeof(vexed_block));
	IRSB **results = malloc(num_bytes * sizeof(IRSB*));

	int processed = 0;
	int cur_idx = 0;
	while (processed < num_bytes)
	{
		debug("Next byte: %02x\n", instructions[processed]);
		results[cur_idx] = vex_inst(guest, instructions + processed, block_addr + processed, 1);
		processed += vge.len[0];
		debug("Processed %d bytes\n", processed);

		assert(vge.n_used == 1);
		cur_idx++;
	}

	vb->irsbs = results;
	vb->num_irsbs = cur_idx;
	return vb;
}

IRSB *vex_block_bytes(VexArch guest, unsigned char *instructions, unsigned int block_addr, unsigned int num_bytes)
{
	debug("Translating %d bytes\n", num_bytes);
	vexed_block *vb = vex_bytes(guest, instructions, block_addr, num_bytes);
	debug("=== GETTING FULL BB IR:\n");
	IRSB *sb = vex_inst(guest, instructions, block_addr, vb->num_irsbs);
	assert(vge.len[0] == num_bytes);

	// TODO: look into deep-freeing if we change memory allocation methods
	free(vb->irsbs);
	free(vb);
	return sb;
}

IRSB *vex_block_inst(VexArch guest, unsigned char *instructions, unsigned int block_addr, unsigned int num_inst)
{
	debug("Translating %d instructions\n", num_inst);

	debug("=== GETTING FULL BB IR:\n");
	IRSB *fullblock = vex_inst(guest, instructions, block_addr, num_inst);
	assert(vge.n_used == 1);

	return fullblock;
}
