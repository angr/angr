#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "pyvex_logging.h"

////////////////////////
// IRConst base class //
////////////////////////

PYVEX_NEW(IRConst)
PYVEX_DEALLOC(IRConst)
PYVEX_METH_STANDARD(IRConst)

static int
pyIRConst_init(pyIRConst *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRConst);
	PyErr_SetString(VexException, "Base IRConst creation not supported.");
	return -1;
}

PYVEX_SETTER(IRConst, wrapped)
PYVEX_GETTER(IRConst, wrapped)
PYVEX_ACCESSOR_ENUM(IRConst, IRConst, wrapped->tag, tag, IRConstTag)

PyObject *pyIRConst_equals(pyIRConst *self, pyIRConst *other)
{
	PYVEX_CHECKTYPE(other, pyIRConstType, Py_RETURN_FALSE);

	if (!eqIRConst(self->wrapped, other->wrapped)) { Py_RETURN_FALSE; }
	Py_RETURN_TRUE;
}

static PyGetSetDef pyIRConst_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRConst, tag),
	PYVEX_ACCESSOR_DEF(IRConst, wrapped),
	{NULL}
};

static PyMethodDef pyIRConst_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRConst),
	{"equals", (PyCFunction)pyIRConst_equals, METH_O, "Checks equality with another const."},
	{NULL}
};

static PyMemberDef pyIRConst_members[] = { {NULL} };
PYVEX_TYPEOBJECT(IRConst);

//////////////////////
// IRConst wrapping //
//////////////////////

PyObject *wrap_IRConst(IRConst *i)
{
	PyTypeObject *t = NULL;

	switch (i->tag)
	{
		PYVEX_WRAPCASE(IRConst, Ico_, U1)
		PYVEX_WRAPCASE(IRConst, Ico_, U8)
		PYVEX_WRAPCASE(IRConst, Ico_, U16)
		PYVEX_WRAPCASE(IRConst, Ico_, U32)
		PYVEX_WRAPCASE(IRConst, Ico_, U64)
		PYVEX_WRAPCASE(IRConst, Ico_, F32)
		PYVEX_WRAPCASE(IRConst, Ico_, F32i)
		PYVEX_WRAPCASE(IRConst, Ico_, F64)
		PYVEX_WRAPCASE(IRConst, Ico_, F64i)
		PYVEX_WRAPCASE(IRConst, Ico_, V128)
		PYVEX_WRAPCASE(IRConst, Ico_, V256)
		default:
			error("PyVEX: Unknown/unsupported IRConstTag %s\n", IRConstTag_to_str(i->tag));
			t = &pyIRStmtType;
	}

	PyObject *args = Py_BuildValue("");
	PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, "IRConst", NULL));
	PyObject *o = PyObject_Call((PyObject *)t, args, kwargs);
	Py_DECREF(args); Py_DECREF(kwargs);
	return (PyObject *)o;
}

////////////////////
// Constant types //
////////////////////

#define PYVEX_IRCONST_SUBCLASS(tag, type, format) \
	int pyIRConst##tag##_init(pyIRConst *self, PyObject *args, PyObject *kwargs) \
	{ \
		PYVEX_WRAP_CONSTRUCTOR(IRConst); \
	 \
		type value; \
		static char *kwlist[] = {"value", NULL}; \
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, format, kwlist, &value)) return -1; \
		self->wrapped = IRConst_##tag(value); \
		return 0; \
	} \
	 \
	PYVEX_ACCESSOR_BUILDVAL(IRConst##tag, IRConst, wrapped->Ico.tag, value, format) \
	 \
	PyGetSetDef pyIRConst##tag##_getseters[] = \
	{ \
		PYVEX_ACCESSOR_DEF(IRConst##tag, value), \
		{NULL} \
	}; \
	 \
	PyMethodDef pyIRConst##tag##_methods[] = { {NULL} }; \
	PYVEX_SUBTYPEOBJECT(tag, IRConst); \

PYVEX_IRCONST_SUBCLASS(U1, unsigned char, "b");
PYVEX_IRCONST_SUBCLASS(U8, unsigned char, "b");
PYVEX_IRCONST_SUBCLASS(U16, unsigned short int, "H");
PYVEX_IRCONST_SUBCLASS(U32, unsigned int, "I");
PYVEX_IRCONST_SUBCLASS(U64, unsigned long long, "K");
PYVEX_IRCONST_SUBCLASS(F32, float, "f");
PYVEX_IRCONST_SUBCLASS(F32i, unsigned int, "I");
PYVEX_IRCONST_SUBCLASS(F64, double, "d");
PYVEX_IRCONST_SUBCLASS(F64i, unsigned long long, "K");
PYVEX_IRCONST_SUBCLASS(V128, unsigned short int, "H");
PYVEX_IRCONST_SUBCLASS(V256, unsigned int, "I");
