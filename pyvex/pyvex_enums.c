#include <libvex.h>
#include <stdio.h>
#include <string.h>
#include "pyvex_macros.h"

//////////////////////////
// IRExprTag translator //
//////////////////////////

const char *IRExprTag_to_str(IRExprTag t)
{
	switch (t)
	{
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Binder)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Get)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_GetI)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_RdTmp)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Qop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Triop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Binop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Unop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Load)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Const)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Mux0X)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_CCall)
		default:
			fprintf(stderr, "PyVEX: Unknown IRExprTag");
			return NULL;
	}
}

// TODO: speed this up
IRExprTag str_to_IRExprTag(const char *s)
{
	PYVEX_ENUMCONV_FROMSTR(Iex_Binder)
	PYVEX_ENUMCONV_FROMSTR(Iex_Get)
	PYVEX_ENUMCONV_FROMSTR(Iex_GetI)
	PYVEX_ENUMCONV_FROMSTR(Iex_RdTmp)
	PYVEX_ENUMCONV_FROMSTR(Iex_Qop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Triop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Binop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Unop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Load)
	PYVEX_ENUMCONV_FROMSTR(Iex_Const)
	PYVEX_ENUMCONV_FROMSTR(Iex_Mux0X)
	PYVEX_ENUMCONV_FROMSTR(Iex_CCall)

	return 0;
}

//////////////////////////
// IRStmtTag translator //
//////////////////////////

const char *IRStmtTag_to_str(IRStmtTag t)
{
	switch (t)
	{
		PYVEX_ENUMCONV_TOSTRCASE(Ist_NoOp) PYVEX_ENUMCONV_TOSTRCASE(Ist_IMark)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_AbiHint)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_Put)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_PutI)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_WrTmp)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_Store)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_CAS)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_LLSC)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_Dirty)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_MBE)
		PYVEX_ENUMCONV_TOSTRCASE(Ist_Exit)
		default:
			fprintf(stderr, "PyVEX: Unknown IRStmtTag");
			return NULL;
	}
}

IRStmtTag str_to_IRStmtTag(const char *s)
{
	PYVEX_ENUMCONV_FROMSTR(Ist_NoOp)
	PYVEX_ENUMCONV_FROMSTR(Ist_IMark)
	PYVEX_ENUMCONV_FROMSTR(Ist_AbiHint)
	PYVEX_ENUMCONV_FROMSTR(Ist_Put)
	PYVEX_ENUMCONV_FROMSTR(Ist_PutI)
	PYVEX_ENUMCONV_FROMSTR(Ist_WrTmp)
	PYVEX_ENUMCONV_FROMSTR(Ist_Store)
	PYVEX_ENUMCONV_FROMSTR(Ist_CAS)
	PYVEX_ENUMCONV_FROMSTR(Ist_LLSC)
	PYVEX_ENUMCONV_FROMSTR(Ist_Dirty)
	PYVEX_ENUMCONV_FROMSTR(Ist_MBE)
	PYVEX_ENUMCONV_FROMSTR(Ist_Exit)

	return 0;
}

//////////////////////////
// IREndness translator //
//////////////////////////

const char *IREndness_to_str(IREndness t)
{
	switch (t)
	{
		PYVEX_ENUMCONV_TOSTRCASE(Iend_LE)
		PYVEX_ENUMCONV_TOSTRCASE(Iend_BE)
		default:
			fprintf(stderr, "PyVEX: Unknown IREndness");
			return NULL;
	}
}

IRStmtTag str_to_IREndness(const char *s)
{
	PYVEX_ENUMCONV_FROMSTR(Iend_LE)
	PYVEX_ENUMCONV_FROMSTR(Iend_BE)

	return 0;
}
