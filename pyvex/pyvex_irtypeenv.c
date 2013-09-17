#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
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

PyObject *pyIRTypeEnv_types(pyIRTypeEnv *self)
{
	PyObject *result = PyTuple_New(self->wrapped->types_used);
	for (int i = 0; i < self->wrapped->types_used; i++)
	{
		const char *type_str;
		PYVEX_ENUM_TOSTR(IRType, self->wrapped->types[i], type_str, return NULL);

		PyObject *wrapped = PyString_FromString(type_str);
		PyTuple_SetItem(result, i, wrapped);
	}
	return result;
}

PyObject *pyIRTypeEnv_newTemp(pyIRTypeEnv *self, PyObject *type)
{
	IRType t = 0;
	const char *t_str = PyString_AsString(type);
	if (!t_str) { PyErr_SetString(VexException, "Unrecognized type argument to IRType.newTemp"); return NULL; }
	PYVEX_ENUM_TOSTR(IRType, t, t_str, return NULL);

	return PyInt_FromLong(newIRTemp(self->wrapped, t));
}

PyObject *pyIRTypeEnv_typeOf(pyIRTypeEnv *self, PyObject *tmp)
{
	IRTemp t = PyInt_AsLong(tmp);
	if (t > self->wrapped->types_used || t < 0)
	{
		PyErr_SetString(VexException, "IRTemp out of range.");
		return NULL;
	}

	const char *typestr;
	PYVEX_ENUM_TOSTR(IRType, self->wrapped->types[t], typestr, return NULL);
	return PyString_FromString(typestr);
}

static PyGetSetDef pyIRTypeEnv_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRTypeEnv, wrapped),
	{NULL}
};

static PyMethodDef pyIRTypeEnv_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRTypeEnv),
	{"types", (PyCFunction)pyIRTypeEnv_types, METH_NOARGS, "Returns a tuple of the IRTypes in the IRTypeEnv"},
	{"newTemp", (PyCFunction)pyIRTypeEnv_newTemp, METH_O, "Creates a new IRTemp in the IRTypeEnv and returns it"},
	{"typeOf", (PyCFunction)pyIRTypeEnv_typeOf, METH_O, "Returns the type of the given IRTemp"},
	{NULL}
};

PYVEX_TYPEOBJECT(IRTypeEnv);
