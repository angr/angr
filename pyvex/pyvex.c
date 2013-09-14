#include <Python.h>
#include "pyvex_types.h"

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

	if (PyType_Ready(&pyIRSBType) < 0)
		return;

	m = Py_InitModule3("pyvex", module_methods, "Python interface to Valgrind's VEX.");

	if (m == NULL)
	  return;

	Py_INCREF(&pyIRSBType);
	PyModule_AddObject(m, "IRSB", (PyObject *)&pyIRSBType);
}
