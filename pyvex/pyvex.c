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

	// ir constants
	PYVEX_INITTYPE(IRConst);
	PYVEX_INITTYPE(IRConstU1);
	PYVEX_INITTYPE(IRConstU8);
	PYVEX_INITTYPE(IRConstU16);
	PYVEX_INITTYPE(IRConstU32);
	PYVEX_INITTYPE(IRConstU64);
	PYVEX_INITTYPE(IRConstF32);
	PYVEX_INITTYPE(IRConstF32i);
	PYVEX_INITTYPE(IRConstF64);
	PYVEX_INITTYPE(IRConstF64i);
	PYVEX_INITTYPE(IRConstV128);
	PYVEX_INITTYPE(IRConstV256);

	// statements
	PYVEX_INITTYPE(IRStmt);
	PYVEX_INITTYPE(IRStmtNoOp);
	PYVEX_INITTYPE(IRStmtIMark);
	PYVEX_INITTYPE(IRStmtAbiHint);
	PYVEX_INITTYPE(IRStmtPut);
	PYVEX_INITTYPE(IRStmtWrTmp);
	PYVEX_INITTYPE(IRStmtStore);
	PYVEX_INITTYPE(IRStmtCAS);
	PYVEX_INITTYPE(IRStmtLLSC);
	PYVEX_INITTYPE(IRStmtExit);

	// expressions
	PYVEX_INITTYPE(IRExpr);
	PYVEX_INITTYPE(IRExprBinder);
	PYVEX_INITTYPE(IRExprGetI);
	PYVEX_INITTYPE(IRExprRdTmp);
	PYVEX_INITTYPE(IRExprGet);
	PYVEX_INITTYPE(IRExprQop);
	PYVEX_INITTYPE(IRExprTriop);
	PYVEX_INITTYPE(IRExprBinop);
	PYVEX_INITTYPE(IRExprUnop);
	PYVEX_INITTYPE(IRExprLoad);
	PYVEX_INITTYPE(IRExprConst);
	PYVEX_INITTYPE(IRExprMux0X);
	PYVEX_INITTYPE(IRExprCCall);

	// callee
	PYVEX_INITTYPE(IRCallee);

	// reg array
	PYVEX_INITTYPE(IRRegArray);

	VexException = PyErr_NewException("pyvex.VexException", NULL, NULL);
	PyModule_AddObject(module, "VexException", VexException);
	//printf("VexException added...\n");

	//debug_on = 1;
	vex_init();
	//printf("Done\n");
}
