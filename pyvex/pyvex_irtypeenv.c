#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "vex/angr_vexir.h"

//////////////////
// Python stuff //
//////////////////

PYVEX_NEW(IRTypeEnv)
PYVEX_DEALLOC(IRTypeEnv)
PYVEX_WRAP(IRTypeEnv)
PYVEX_METH_STANDARD(IRTypeEnv)

static int
pyIRTypeEnv_init(pyIRTypeEnv *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { self->wrapped = emptyIRTypeEnv(); return 0; }
	PYVEX_WRAP_CONSTRUCTOR(IRTypeEnv);

	PyErr_SetString(VexException, "Unexpected arguments provided.");
	return -1;
}

static PyMemberDef pyIRTypeEnv_members[] =
{
	{NULL}
};

PYVEX_SETTER(IRTypeEnv, wrapped)
PYVEX_GETTER(IRTypeEnv, wrapped)

static PyGetSetDef pyIRTypeEnv_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRTypeEnv, wrapped),
	{NULL}
};

static PyMethodDef pyIRTypeEnv_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRTypeEnv),
	{NULL}
};

PYVEX_TYPEOBJECT(IRTypeEnv);
