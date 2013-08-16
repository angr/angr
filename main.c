/*
 * This code is GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <argtable2.h>

#include "common.h"
#include "vexir.h"
#include "libvex.h"

///////////////////
// CONFIGURATION //
///////////////////

int main(int argc, char **argv)
{
	// FUCK
	//signal(SIGINT, fucking_quit);

	//
	// Command-line arguments
	//

	// general
	struct arg_lit *verb = arg_lit0("v", "verbose", "verbose output");
	struct arg_lit *help = arg_lit0("h", "help", "verbose output");
	struct arg_end *end = arg_end(20);

	// translation
	struct arg_str *binfile = arg_str0("b", "binary", "<file>", "binary file to read");
	struct arg_int *file_addr = arg_int0("f", "fileaddr", "<address>", "file address to read instructions from");
	struct arg_int *mem_addr = arg_int0("m", "memaddr", "<address>", "file address to read instructions from");
	struct arg_int *num_bytes = arg_int0("n", "numbytes", "<number>", "number of bytes to vex");
	struct arg_int *num_inst = arg_int0("i", "numinst", "<number>", "number of instructions to vex");

	// Do the argument parsing
	void *argtable[] = {verb, help, binfile, file_addr, mem_addr, num_bytes, num_inst, end};
	int nerrors = arg_parse(argc,argv,argtable);

	if (help->count)
	{
		printf("Awesome binary analysis platform.\n\nUsage:\n");
		printf("# %s ", argv[0]);
		arg_print_syntaxv(stdout, argtable, "\n\n");
		arg_print_glossary(stdout, argtable, "\t%-25s %s\n");
		exit(0);
	}

	if (nerrors > 0)
	{
		printf("# %s ", argv[0]);
		arg_print_syntaxv(stdout, argtable, "\n");

		printf("\n");
		arg_print_errors(stdout,end,argv[0]);
		exit(1);
	}

	if (verb->count) debug_on = 1;

	// actual stuff
	debug("Initializing VEX...\n");
	vex_init();
	debug("VEX initialized!\n");

	info("Loading %d bytes starting at %p in file %s with memory address %p\n", num_bytes->ival[0], file_addr->ival[0], binfile->sval[0], mem_addr->ival[0]);

	FILE *infile = fopen(binfile->sval[0], "rb");
	unsigned char *buf = malloc(num_bytes->ival[0]);
	fseek(infile, file_addr->ival[0], SEEK_SET);
	fread(buf, 1, num_bytes->ival[0], infile);

	debug("Translating...\n");
	//IRSB *result_sb = vex_insn(VexArchAMD64, buf, mem_addr->ival[0]);
	//debug("Got superblock at %p\n", result_sb);
	//debug("--- %d extents.\n", vge.n_used);
	//for (int i = 0; i < vge.n_used; i++) debug("------ %d bytes.\n", vge.len[i]);
	IRSB *sb;

	if (num_bytes->count)
	{
		IRSB *sb = vex_block_bytes(VexArchAMD64, buf, mem_addr->ival[0], num_bytes->ival[0]);
	}

	if (num_inst->count)
	{
		IRSB *sb = vex_block_inst(VexArchAMD64, buf, mem_addr->ival[0], num_inst->ival[0]);
	}

	arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));
}


