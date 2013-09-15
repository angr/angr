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

	if (PyType_Ready(&pyIRSBType) < 0) { printf("pyIRSBType not ready...\n"); return; }
	if (PyType_Ready(&pyIRStmtType) < 0) { printf("pyIRStmtType not ready...\n"); return; }

	module = Py_InitModule3("pyvex", module_methods, "Python interface to Valgrind's VEX.");
	if (module == NULL) return;

	Py_INCREF(&pyIRSBType); PyModule_AddObject(module, "IRSB", (PyObject *)&pyIRSBType);
	Py_INCREF(&pyIRStmtType); PyModule_AddObject(module, "IRStmt", (PyObject *)&pyIRStmtType);

	VexException = PyErr_NewException("pyvex.VexException", NULL, NULL);
	PyModule_AddObject(module, "VexException", VexException);
	//printf("VexException added...\n");

	//debug_on = 1;
	vex_init();
	//printf("Done\n");
}
