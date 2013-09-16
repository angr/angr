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

	// statements
	PYVEX_INITTYPE(IRStmt);
	PYVEX_INITTYPE(IRStmtNoOp);
	PYVEX_INITTYPE(IRStmtIMark);
	PYVEX_INITTYPE(IRStmtAbiHint);
	PYVEX_INITTYPE(IRStmtPut);

	// expressions
	PYVEX_INITTYPE(IRExpr);
	PYVEX_INITTYPE(IRExprRdTmp);

	VexException = PyErr_NewException("pyvex.VexException", NULL, NULL);
	PyModule_AddObject(module, "VexException", VexException);
	//printf("VexException added...\n");

	//debug_on = 1;
	vex_init();
	//printf("Done\n");
}
