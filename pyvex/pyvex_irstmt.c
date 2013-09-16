#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "vex/angr_vexir.h"

//////////////////
// Python stuff //
//////////////////

PYVEX_NEW(IRStmt)
PYVEX_DEALLOC(IRStmt)
PYVEX_WRAP(IRStmt)
PYVEX_METH_STANDARD(IRStmt)

static int
pyIRStmt_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { PyErr_SetString(VexException, "Not enough arguments provided."); return -1; }
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	PyObject *tag = NULL;
	static char *kwlist[] = {"wrap", "tag", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OS", kwlist, &wrap_object, &tag)) return -1;

	if (tag)
	{
		PyErr_SetString(VexException, "TODO: implement");
		Py_DECREF(tag);
		return -1;
	}
	else
	{
		PyErr_SetString(VexException, "Not enough arguments provided.");
		return -1;
	}

	return 0;
}

static PyMemberDef pyIRStmt_members[] =
{
	{NULL}
};

PYVEX_SETTER(IRStmt, wrapped)
PYVEX_GETTER(IRStmt, wrapped)

static PyGetSetDef pyIRStmt_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmt, wrapped),
	{NULL}
};

static PyObject *pyIRStmt_isFlat(pyIRStmt* self)
{
	if (isFlatIRStmt(self->wrapped)) { Py_RETURN_TRUE; }
	Py_RETURN_FALSE;
}

static PyMethodDef pyIRStmt_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRStmt),
	{"isFlat", (PyCFunction)pyIRStmt_isFlat, METH_NOARGS, "Returns true if IRStmt is flat, false otherwise."},
	{NULL}
};

PYVEX_TYPEOBJECT(IRStmt);
