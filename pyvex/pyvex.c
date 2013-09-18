#include <Python.h>
#include "vex/angr_vexir.h"
#include "vex/angr_common.h"
#include "pyvex_types.h"

PyObject *VexException;
PyObject *module;

static PyMethodDef module_methods[] = {
	{NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initpyvex(void) 
{
	//printf("Module loading...\n");
	module = Py_InitModule3("pyvex", module_methods, "Python interface to Valgrind's VEX.");
	if (module == NULL) return;

	//
	// Ready types
	//
	PYVEX_INITTYPE(IRSB);
	PYVEX_INITTYPE(IRTypeEnv);
	PYVEX_INITTYPE(IRCallee);
	PYVEX_INITTYPE(IRRegArray);

	// ir constants
	PYVEX_INITTYPE(IRConst);
	PYVEX_INITSUBTYPE(IRConst, U1);
	PYVEX_INITSUBTYPE(IRConst, U8);
	PYVEX_INITSUBTYPE(IRConst, U16);
	PYVEX_INITSUBTYPE(IRConst, U32);
	PYVEX_INITSUBTYPE(IRConst, U64);
	PYVEX_INITSUBTYPE(IRConst, F32);
	PYVEX_INITSUBTYPE(IRConst, F32i);
	PYVEX_INITSUBTYPE(IRConst, F64);
	PYVEX_INITSUBTYPE(IRConst, F64i);
	PYVEX_INITSUBTYPE(IRConst, V128);
	PYVEX_INITSUBTYPE(IRConst, V256);

	// statements
	PYVEX_INITTYPE(IRStmt);
	PYVEX_INITSUBTYPE(IRStmt, NoOp);
	PYVEX_INITSUBTYPE(IRStmt, IMark);
	PYVEX_INITSUBTYPE(IRStmt, AbiHint);
	PYVEX_INITSUBTYPE(IRStmt, Put);
	PYVEX_INITSUBTYPE(IRStmt, PutI);
	PYVEX_INITSUBTYPE(IRStmt, WrTmp);
	PYVEX_INITSUBTYPE(IRStmt, Store);
	PYVEX_INITSUBTYPE(IRStmt, CAS);
	PYVEX_INITSUBTYPE(IRStmt, LLSC);
	PYVEX_INITSUBTYPE(IRStmt, MBE);
	PYVEX_INITSUBTYPE(IRStmt, Exit);

	// expressions
	PYVEX_INITTYPE(IRExpr);
	PYVEX_INITSUBTYPE(IRExpr, Binder);
	PYVEX_INITSUBTYPE(IRExpr, GetI);
	PYVEX_INITSUBTYPE(IRExpr, RdTmp);
	PYVEX_INITSUBTYPE(IRExpr, Get);
	PYVEX_INITSUBTYPE(IRExpr, Qop);
	PYVEX_INITSUBTYPE(IRExpr, Triop);
	PYVEX_INITSUBTYPE(IRExpr, Binop);
	PYVEX_INITSUBTYPE(IRExpr, Unop);
	PYVEX_INITSUBTYPE(IRExpr, Load);
	PYVEX_INITSUBTYPE(IRExpr, Const);
	PYVEX_INITSUBTYPE(IRExpr, Mux0X);
	PYVEX_INITSUBTYPE(IRExpr, CCall);

	VexException = PyErr_NewException("pyvex.VexException", NULL, NULL);
	PyModule_AddObject(module, "VexException", VexException);
	//printf("VexException added...\n");

	//debug_on = 1;
	vex_init();
	//printf("Done\n");
}
