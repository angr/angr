#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"

///////////////////////
// IRExpr base class //
///////////////////////

PYVEX_NEW(IRExpr)
PYVEX_DEALLOC(IRExpr)
PYVEX_METH_STANDARD(IRExpr)

static int
pyIRExpr_init(pyIRExpr *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRExpr);
	PyErr_SetString(VexException, "Base IRExpr creation not supported..");
	return -1;
}

PYVEX_SETTER(IRExpr, wrapped)
PYVEX_GETTER(IRExpr, wrapped)
PYVEX_ACCESSOR_ENUM(IRExpr, IRExpr, wrapped->tag, tag, IRExprTag)

static PyGetSetDef pyIRExpr_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRExpr, wrapped),
	PYVEX_ACCESSOR_DEF(IRExpr, tag),
	{NULL}
};

static PyObject *pyIRExpr_atomic(pyIRExpr* self)
{
	if (isIRAtom(self->wrapped)) { Py_RETURN_TRUE; }
	Py_RETURN_FALSE;
}

static PyMethodDef pyIRExpr_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRExpr),
	{"atomic", (PyCFunction)pyIRExpr_atomic, METH_NOARGS, "Returns true if IRExpr is atomic (RdTmp or Const), false otherwise."},
	{NULL}
};

static PyMemberDef pyIRExpr_members[] = { {NULL} };
PYVEX_TYPEOBJECT(IRExpr);

// wrap functionality
PyObject *wrap_IRExpr(IRExpr *i)
{
	PyTypeObject *t = NULL;

	switch (i->tag)
	{
		//PYVEX_WRAPCASE(IRExpr, Iex_, Binder)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Get)
		//PYVEX_WRAPCASE(IRExpr, Iex_, GetI)
		PYVEX_WRAPCASE(IRExpr, Iex_, RdTmp)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Qop)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Triop)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Binop)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Unop)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Load)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Const)
		//PYVEX_WRAPCASE(IRExpr, Iex_, Mux0X)
		//PYVEX_WRAPCASE(IRExpr, Iex_, CCall)
		default:
			fprintf(stderr, "PyVEX: Unknown/unsupported IRExprTag %s\n", IRExprTag_to_str(i->tag));
			t = &pyIRExprType;
	}

	PyObject *args = Py_BuildValue("");
	PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, "IRExpr", NULL));
	PyObject *o = PyObject_Call((PyObject *)t, args, kwargs);
	Py_DECREF(args); Py_DECREF(kwargs);
	return (PyObject *)o;
}

//////////////////
// RdTmp IRExpr //
//////////////////

static int
pyIRExprRdTmp_init(pyIRExpr *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRExpr);

	UInt tmp = 0;
	static char *kwlist[] = {"tmp", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "I|O", kwlist, &tmp, &wrap_object)) return -1;

	self->wrapped = IRExpr_RdTmp(tmp);
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRExprRdTmp, IRExpr, wrapped->Iex.RdTmp.tmp, tmp, "I")

static PyGetSetDef pyIRExprRdTmp_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRExprRdTmp, tmp),
	{NULL}
};

static PyMethodDef pyIRExprRdTmp_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRExprRdTmp, IRExpr);

