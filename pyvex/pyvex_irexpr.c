#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "vex/angr_vexir.h"

//////////////////////////
// IRExprTag translator //
//////////////////////////

static const char *IRExprTag_to_str(IRExprTag t)
{
	switch (t)
	{
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Binder)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Get)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_GetI)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_RdTmp)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Qop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Triop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Binop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Unop)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Load)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Const)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_Mux0X)
		PYVEX_ENUMCONV_TOSTRCASE(Iex_CCall)
		default:
			fprintf(stderr, "PyVEX: Unknown IRExprTag");
			return NULL;
	}
}

// TODO: speed this up
static IRExprTag str_to_IRExprTag(const char *s)
{
	PYVEX_ENUMCONV_FROMSTR(Iex_Binder)
	PYVEX_ENUMCONV_FROMSTR(Iex_Get)
	PYVEX_ENUMCONV_FROMSTR(Iex_GetI)
	PYVEX_ENUMCONV_FROMSTR(Iex_RdTmp)
	PYVEX_ENUMCONV_FROMSTR(Iex_Qop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Triop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Binop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Unop)
	PYVEX_ENUMCONV_FROMSTR(Iex_Load)
	PYVEX_ENUMCONV_FROMSTR(Iex_Const)
	PYVEX_ENUMCONV_FROMSTR(Iex_Mux0X)
	PYVEX_ENUMCONV_FROMSTR(Iex_CCall)

	return 0;
}

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
PYVEX_SETTAG(IRExpr)
PYVEX_GETTAG(IRExpr)

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
		//PYVEX_WRAPCASE(IRExpr, Iex, Binder)
		//PYVEX_WRAPCASE(IRExpr, Iex, Get)
		//PYVEX_WRAPCASE(IRExpr, Iex, GetI)
		PYVEX_WRAPCASE(IRExpr, Iex, RdTmp)
		//PYVEX_WRAPCASE(IRExpr, Iex, Qop)
		//PYVEX_WRAPCASE(IRExpr, Iex, Triop)
		//PYVEX_WRAPCASE(IRExpr, Iex, Binop)
		//PYVEX_WRAPCASE(IRExpr, Iex, Unop)
		//PYVEX_WRAPCASE(IRExpr, Iex, Load)
		//PYVEX_WRAPCASE(IRExpr, Iex, Const)
		//PYVEX_WRAPCASE(IRExpr, Iex, Mux0X)
		//PYVEX_WRAPCASE(IRExpr, Iex, CCall)
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

PYVEX_GETTER_BUILDVAL(IRExprRdTmp, IRExpr, wrapped->Iex.RdTmp.tmp, tmp, "I")
PYVEX_SETTER_BUILDVAL(IRExprRdTmp, IRExpr, wrapped->Iex.RdTmp.tmp, tmp, "I")

static PyGetSetDef pyIRExprRdTmp_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRExprRdTmp, tmp),
	{NULL}
};

static PyMethodDef pyIRExprRdTmp_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRExprRdTmp, IRExpr);
