#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "vex/angr_vexir.h"

///////////////////////
// IRStmt base class //
///////////////////////

PYVEX_NEW(IRStmt)
PYVEX_DEALLOC(IRStmt)
PYVEX_METH_STANDARD(IRStmt)

static int
pyIRStmt_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);
	PyErr_SetString(VexException, "Base IRStmt creation not supported.");
	return -1;
}

PYVEX_SETTER(IRStmt, wrapped)
PYVEX_GETTER(IRStmt, wrapped)
PYVEX_ACCESSOR_ENUM(IRStmt, IRStmt, IRStmtTag, wrapped->tag, tag)

static PyGetSetDef pyIRStmt_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmt, wrapped),
	PYVEX_ACCESSOR_DEF(IRStmt, tag),
	{NULL}
};

static PyObject *pyIRStmt_flat(pyIRStmt* self)
{
	if (isFlatIRStmt(self->wrapped)) { Py_RETURN_TRUE; }
	Py_RETURN_FALSE;
}

static PyMethodDef pyIRStmt_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRStmt),
	{"flat", (PyCFunction)pyIRStmt_flat, METH_NOARGS, "Returns true if IRStmt is flat, false otherwise."},
	{NULL}
};

static PyMemberDef pyIRStmt_members[] = { {NULL} };
PYVEX_TYPEOBJECT(IRStmt);

// wrap functionality
PyObject *wrap_IRStmt(IRStmt *i)
{
	PyTypeObject *t = NULL;

	switch (i->tag)
	{
		PYVEX_WRAPCASE(IRStmt, Ist_, NoOp)
		PYVEX_WRAPCASE(IRStmt, Ist_, IMark)
		PYVEX_WRAPCASE(IRStmt, Ist_, AbiHint)
		PYVEX_WRAPCASE(IRStmt, Ist_, Put)
		//PYVEX_WRAPCASE(IRStmt, Ist_, PutI)
		PYVEX_WRAPCASE(IRStmt, Ist_, WrTmp)
		PYVEX_WRAPCASE(IRStmt, Ist_, Store)
		PYVEX_WRAPCASE(IRStmt, Ist_, CAS)
		//PYVEX_WRAPCASE(IRStmt, Ist_, LLSC)
		//PYVEX_WRAPCASE(IRStmt, Ist_, Dirty)
		//PYVEX_WRAPCASE(IRStmt, Ist_, MBE)
		//PYVEX_WRAPCASE(IRStmt, Ist_, Exit)
		default:
			fprintf(stderr, "PyVEX: Unknown/unsupported IRStmtTag %s\n", IRStmtTag_to_str(i->tag));
			t = &pyIRStmtType;
	}

	PyObject *args = Py_BuildValue("");
	PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, "IRStmt", NULL));
	PyObject *o = PyObject_Call((PyObject *)t, args, kwargs);
	Py_DECREF(args); Py_DECREF(kwargs);
	return (PyObject *)o;
}

/////////////////
// NoOp IRStmt //
/////////////////

static int
pyIRStmtNoOp_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { self->wrapped = IRStmt_NoOp(); return 0; }
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	PyErr_SetString(VexException, "Unexpected arguments provided to constructor.");
	return -1;
}

static PyMethodDef pyIRStmtNoOp_methods[] = { {NULL} };
static PyGetSetDef pyIRStmtNoOp_getseters[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtNoOp, IRStmt);

//////////////////
// IMark IRStmt //
//////////////////

static int
pyIRStmtIMark_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	Addr64 addr = 0;
	Int len = 0;
	UChar delta = 0;

	static char *kwlist[] = {"addr", "len", "delta", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Kib|O", kwlist, &addr, &len, &delta, &wrap_object)) return -1;

	self->wrapped = IRStmt_IMark(addr, len, delta);
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRStmtIMark, IRStmt, wrapped->Ist.IMark.addr, addr, "K")
PYVEX_ACCESSOR_BUILDVAL(IRStmtIMark, IRStmt, wrapped->Ist.IMark.len, len, "i")
PYVEX_ACCESSOR_BUILDVAL(IRStmtIMark, IRStmt, wrapped->Ist.IMark.delta, delta, "b")

static PyGetSetDef pyIRStmtIMark_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtIMark, addr),
	PYVEX_ACCESSOR_DEF(IRStmtIMark, len),
	PYVEX_ACCESSOR_DEF(IRStmtIMark, delta),
	{NULL}
};

static PyMethodDef pyIRStmtIMark_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtIMark, IRStmt);

////////////////////
// AbiHint IRStmt //
////////////////////

static int
pyIRStmtAbiHint_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	pyIRExpr *base;
	Int len = 0;
	pyIRExpr *nia;

	static char *kwlist[] = {"base", "len", "nia", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OiO|O", kwlist, &base, &len, &nia, &wrap_object)) return -1;
	PYVEX_CHECKTYPE(base, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(nia, pyIRExprType, return -1)

	self->wrapped = IRStmt_AbiHint(base->wrapped, len, nia->wrapped);
	return 0;
}

PYVEX_ACCESSOR_WRAPPED(IRStmtAbiHint, IRStmt, wrapped->Ist.AbiHint.base, base, IRExpr)
PYVEX_ACCESSOR_BUILDVAL(IRStmtAbiHint, IRStmt, wrapped->Ist.AbiHint.len, len, "i")
PYVEX_ACCESSOR_WRAPPED(IRStmtAbiHint, IRStmt, wrapped->Ist.AbiHint.nia, nia, IRExpr)

static PyGetSetDef pyIRStmtAbiHint_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtAbiHint, base),
	PYVEX_ACCESSOR_DEF(IRStmtAbiHint, len),
	PYVEX_ACCESSOR_DEF(IRStmtAbiHint, nia),
	{NULL}
};

static PyMethodDef pyIRStmtAbiHint_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtAbiHint, IRStmt);

////////////////
// Put IRStmt //
////////////////

static int
pyIRStmtPut_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	Int offset = 0;
	pyIRExpr *data;

	static char *kwlist[] = {"offset", "data", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO|O", kwlist, &offset, &data, &wrap_object)) return -1;
	PYVEX_CHECKTYPE(data, pyIRExprType, return -1)

	self->wrapped = IRStmt_Put(offset, data->wrapped);
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRStmtPut, IRStmt, wrapped->Ist.Put.offset, offset, "i")
PYVEX_ACCESSOR_WRAPPED(IRStmtPut, IRStmt, wrapped->Ist.Put.data, data, IRExpr)

static PyGetSetDef pyIRStmtPut_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtPut, offset),
	PYVEX_ACCESSOR_DEF(IRStmtPut, data),
	{NULL}
};

static PyMethodDef pyIRStmtPut_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtPut, IRStmt);

//////////////////
// WrTmp IRStmt //
//////////////////

static int
pyIRStmtWrTmp_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	IRTemp tmp = 0;
	pyIRExpr *data;

	static char *kwlist[] = {"tmp", "data", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO|O", kwlist, &tmp, &data, &wrap_object)) return -1;
	PYVEX_CHECKTYPE(data, pyIRExprType, return -1)

	self->wrapped = IRStmt_WrTmp(tmp, data->wrapped);
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRStmtWrTmp, IRStmt, wrapped->Ist.WrTmp.tmp, tmp, "i")
PYVEX_ACCESSOR_WRAPPED(IRStmtWrTmp, IRStmt, wrapped->Ist.WrTmp.data, data, IRExpr)

static PyGetSetDef pyIRStmtWrTmp_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtWrTmp, tmp),
	PYVEX_ACCESSOR_DEF(IRStmtWrTmp, data),
	{NULL}
};

static PyMethodDef pyIRStmtWrTmp_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtWrTmp, IRStmt);

//////////////////
// Store IRStmt //
//////////////////

static int
pyIRStmtStore_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	IREndness endness;
	char *endness_str;
	pyIRExpr *addr;
	pyIRExpr *data;

	static char *kwlist[] = {"endness", "addr", "data", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sOO|O", kwlist, &endness_str, &addr, &data, &wrap_object)) return -1;
	PYVEX_CHECKTYPE(addr, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(data, pyIRExprType, return -1)
	endness = str_to_IREndness(endness_str);
	if (endness == 0) { PyErr_SetString(VexException, "Unrecognized IREndness."); return -1; }

	self->wrapped = IRStmt_Store(endness, addr->wrapped, data->wrapped);
	return 0;
}

PYVEX_ACCESSOR_ENUM(IRStmtStore, IRStmt, IREndness, wrapped->Ist.Store.end, endness)
PYVEX_ACCESSOR_WRAPPED(IRStmtStore, IRStmt, wrapped->Ist.Store.addr, addr, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtStore, IRStmt, wrapped->Ist.Store.data, data, IRExpr)

static PyGetSetDef pyIRStmtStore_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtStore, endness),
	PYVEX_ACCESSOR_DEF(IRStmtStore, addr),
	PYVEX_ACCESSOR_DEF(IRStmtStore, data),
	{NULL}
};

static PyMethodDef pyIRStmtStore_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtStore, IRStmt);

//////////////////
// CAS IRStmt //
//////////////////

static int
pyIRStmtCAS_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	IRTemp oldHi;
	IRTemp oldLo;
	IREndness endness;
	char *endness_str;
	pyIRExpr *addr;
	pyIRExpr *expdHi;
	pyIRExpr *expdLo;
	pyIRExpr *dataHi;
	pyIRExpr *dataLo;

	static char *kwlist[] = {"oldHi", "oldLo", "endness", "addr", "expdHi", "expdLo", "dataHi", "dataLo", "wrap", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iisOOOOO|O", kwlist, &oldHi, &oldLo, &endness_str, &addr, &expdHi, &expdLo,
				&dataHi, &dataLo, &wrap_object)) return -1;
	PYVEX_CHECKTYPE(expdHi, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(expdLo, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(dataHi, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(dataLo, pyIRExprType, return -1)
	endness = str_to_IREndness(endness_str);
	if (endness == 0) { PyErr_SetString(VexException, "Unrecognized IREndness."); return -1; }

	self->wrapped = IRStmt_CAS(mkIRCAS(oldHi, oldLo, endness, addr->wrapped, expdHi->wrapped, expdLo->wrapped,
				dataHi->wrapped, dataLo->wrapped));
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->oldHi, oldHi, "i")
PYVEX_ACCESSOR_BUILDVAL(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->oldLo, oldLo, "i")
PYVEX_ACCESSOR_ENUM(IRStmtCAS, IRStmt, IREndness, wrapped->Ist.CAS.details->end, endness)
PYVEX_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->addr, addr, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->expdHi, expdHi, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->expdLo, expdLo, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->dataHi, dataHi, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->dataLo, dataLo, IRExpr)

static PyGetSetDef pyIRStmtCAS_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtCAS, oldHi),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, oldLo),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, endness),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, addr),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, expdHi),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, expdLo),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, dataHi),
	PYVEX_ACCESSOR_DEF(IRStmtCAS, dataLo),
	{NULL}
};

static PyMethodDef pyIRStmtCAS_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtCAS, IRStmt);
