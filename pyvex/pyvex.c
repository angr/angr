#include <Python.h>
#include "vex/angr_vexir.h"
#include "vex/angr_common.h"
#include "pyvex_types.h"
//#include "pyvex_irsb.c"

PyObject *VexException;

static PyMethodDef module_methods[] = {
	{NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initpyvex(void) 
{
	PyObject* m;

	//printf("Module loading...\n");

	if (PyType_Ready(&pyIRSBType) < 0)
	{
		printf("Type not ready...\n");
		return;
	}

	m = Py_InitModule3("pyvex", module_methods, "Python interface to Valgrind's VEX.");
	//printf("Module inited...\n");

	if (m == NULL)
	  return;

	Py_INCREF(&pyIRSBType);
	PyModule_AddObject(m, "IRSB", (PyObject *)&pyIRSBType);
	//printf("IRSB added...\n");

	VexException = PyErr_NewException("pyvex.VexException", NULL, NULL);
	PyModule_AddObject(m, "VexException", VexException);
	//printf("VexException added...\n");

	//debug_on = 1;
	vex_init();
	//printf("Done\n");
}
