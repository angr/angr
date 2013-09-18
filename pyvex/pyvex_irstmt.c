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
PYVEX_ACCESSOR_ENUM(IRStmt, IRStmt, wrapped->tag, tag, IRStmtTag)

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
		PYVEX_WRAPCASE(IRStmt, Ist_, PutI)
		PYVEX_WRAPCASE(IRStmt, Ist_, WrTmp)
		PYVEX_WRAPCASE(IRStmt, Ist_, Store)
		PYVEX_WRAPCASE(IRStmt, Ist_, CAS)
		PYVEX_WRAPCASE(IRStmt, Ist_, LLSC)
		//PYVEX_WRAPCASE(IRStmt, Ist_, Dirty)
		PYVEX_WRAPCASE(IRStmt, Ist_, MBE)
		PYVEX_WRAPCASE(IRStmt, Ist_, Exit)
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

	Addr64 addr;
	Int len;
	UChar delta;

	static char *kwlist[] = {"addr", "len", "delta", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Kib", kwlist, &addr, &len, &delta)) return -1;

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
	Int len;
	pyIRExpr *nia;

	static char *kwlist[] = {"base", "len", "nia", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OiO", kwlist, &base, &len, &nia)) return -1;
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

	Int offset;
	pyIRExpr *data;

	static char *kwlist[] = {"offset", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO", kwlist, &offset, &data)) return -1;
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

/////////////////
// PutI IRStmt //
/////////////////

static int
pyIRStmtPutI_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	pyIRRegArray *descr;
	pyIRExpr *ix;
	Int bias;
	pyIRExpr *data;

	static char *kwlist[] = {"description", "index", "bias", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOiO", kwlist, &descr, &ix, &bias, &data)) return -1;
	PYVEX_CHECKTYPE(descr, pyIRRegArrayType, return -1)
	PYVEX_CHECKTYPE(ix, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(data, pyIRExprType, return -1)

	self->wrapped = IRStmt_PutI(mkIRPutI(descr->wrapped, ix->wrapped, bias, data->wrapped));
	return 0;
}

PYVEX_ACCESSOR_WRAPPED(IRStmtPutI, IRStmt, wrapped->Ist.PutI.details->descr, description, IRRegArray)
PYVEX_ACCESSOR_WRAPPED(IRStmtPutI, IRStmt, wrapped->Ist.PutI.details->ix, index, IRExpr)
PYVEX_ACCESSOR_BUILDVAL(IRStmtPutI, IRStmt, wrapped->Ist.PutI.details->bias, bias, "i")
PYVEX_ACCESSOR_WRAPPED(IRStmtPutI, IRStmt, wrapped->Ist.PutI.details->data, data, IRExpr)

static PyGetSetDef pyIRStmtPutI_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtPutI, description),
	PYVEX_ACCESSOR_DEF(IRStmtPutI, index),
	PYVEX_ACCESSOR_DEF(IRStmtPutI, bias),
	PYVEX_ACCESSOR_DEF(IRStmtPutI, data),
	{NULL}
};

static PyMethodDef pyIRStmtPutI_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtPutI, IRStmt);

//////////////////
// WrTmp IRStmt //
//////////////////

static int
pyIRStmtWrTmp_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	IRTemp tmp;
	pyIRExpr *data;

	static char *kwlist[] = {"tmp", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "IO", kwlist, &tmp, &data)) return -1;
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

	static char *kwlist[] = {"endness", "addr", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sOO", kwlist, &endness_str, &addr, &data)) return -1;
	PYVEX_CHECKTYPE(addr, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(data, pyIRExprType, return -1)
	PYVEX_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = IRStmt_Store(endness, addr->wrapped, data->wrapped);
	return 0;
}

PYVEX_ACCESSOR_ENUM(IRStmtStore, IRStmt, wrapped->Ist.Store.end, endness, IREndness)
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

////////////////
// CAS IRStmt //
////////////////

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

	static char *kwlist[] = {"oldHi", "oldLo", "endness", "addr", "expdHi", "expdLo", "dataHi", "dataLo", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "IIsOOOOO", kwlist, &oldHi, &oldLo, &endness_str, &addr, &expdHi, &expdLo,
				&dataHi, &dataLo)) return -1;
	PYVEX_CHECKTYPE(expdHi, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(expdLo, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(dataHi, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(dataLo, pyIRExprType, return -1)
	PYVEX_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = IRStmt_CAS(mkIRCAS(oldHi, oldLo, endness, addr->wrapped, expdHi->wrapped, expdLo->wrapped,
				dataHi->wrapped, dataLo->wrapped));
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->oldHi, oldHi, "i")
PYVEX_ACCESSOR_BUILDVAL(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->oldLo, oldLo, "i")
PYVEX_ACCESSOR_ENUM(IRStmtCAS, IRStmt, wrapped->Ist.CAS.details->end, endness, IREndness)
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

/////////////////
// LLSC IRStmt //
/////////////////

static int
pyIRStmtLLSC_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	IREndness endness;
	char *endness_str;
	IRTemp result;
	pyIRExpr *addr;
	pyIRExpr *storedata;

	static char *kwlist[] = {"endness", "result", "addr", "storedata", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sIOO", kwlist, &endness_str, &result, &addr, &storedata)) return -1;
	PYVEX_CHECKTYPE(addr, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(storedata, pyIRExprType, return -1)
	PYVEX_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = IRStmt_LLSC(endness, result, addr->wrapped, storedata->wrapped);
	return 0;
}

PYVEX_ACCESSOR_BUILDVAL(IRStmtLLSC, IRStmt, wrapped->Ist.LLSC.result, result, "i")
PYVEX_ACCESSOR_ENUM(IRStmtLLSC, IRStmt, wrapped->Ist.LLSC.end, endness, IREndness)
PYVEX_ACCESSOR_WRAPPED(IRStmtLLSC, IRStmt, wrapped->Ist.LLSC.addr, addr, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtLLSC, IRStmt, wrapped->Ist.LLSC.storedata, storedata, IRExpr)

static PyGetSetDef pyIRStmtLLSC_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtLLSC, endness),
	PYVEX_ACCESSOR_DEF(IRStmtLLSC, result),
	PYVEX_ACCESSOR_DEF(IRStmtLLSC, addr),
	PYVEX_ACCESSOR_DEF(IRStmtLLSC, storedata),
	{NULL}
};

static PyMethodDef pyIRStmtLLSC_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtLLSC, IRStmt);

/////////////////
// MBE IRStmt //
/////////////////

static int
pyIRStmtMBE_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	IRMBusEvent mb; char *mb_str;

	static char *kwlist[] = {"jumpkind", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &mb_str)) return -1;
	PYVEX_ENUM_FROMSTR(IRMBusEvent, mb, mb_str, return -1);

	self->wrapped = IRStmt_MBE(mb);
	return 0;
}

PYVEX_ACCESSOR_ENUM(IRStmtMBE, IRStmt, wrapped->Ist.MBE.event, event, IRMBusEvent)

static PyGetSetDef pyIRStmtMBE_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtMBE, event),
	{NULL}
};

static PyMethodDef pyIRStmtMBE_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtMBE, IRStmt);

/////////////////
// Exit IRStmt //
/////////////////

static int
pyIRStmtExit_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRStmt);

	pyIRExpr *guard;
	pyIRConst *dst;
	IRJumpKind jk; char *jk_str;
	int offsIP;

	static char *kwlist[] = {"guard", "jumpkind", "dst", "offsIP", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OsOi", kwlist, &guard, &jk_str, &dst, &offsIP)) return -1;
	PYVEX_CHECKTYPE(guard, pyIRExprType, return -1)
	PYVEX_CHECKTYPE(dst, pyIRConstType, return -1)
	PYVEX_ENUM_FROMSTR(IRJumpKind, jk, jk_str, return -1);

	self->wrapped = IRStmt_Exit(guard->wrapped, jk, dst->wrapped, offsIP);
	return 0;
}

PYVEX_ACCESSOR_WRAPPED(IRStmtExit, IRStmt, wrapped->Ist.Exit.guard, guard, IRExpr)
PYVEX_ACCESSOR_WRAPPED(IRStmtExit, IRStmt, wrapped->Ist.Exit.dst, dst, IRConst)
PYVEX_ACCESSOR_ENUM(IRStmtExit, IRStmt, wrapped->Ist.Exit.jk, jumpkind, IRJumpKind)
PYVEX_ACCESSOR_BUILDVAL(IRStmtExit, IRStmt, wrapped->Ist.Exit.offsIP, offsIP, "i")

static PyGetSetDef pyIRStmtExit_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRStmtExit, guard),
	PYVEX_ACCESSOR_DEF(IRStmtExit, dst),
	PYVEX_ACCESSOR_DEF(IRStmtExit, jumpkind),
	PYVEX_ACCESSOR_DEF(IRStmtExit, offsIP),
	{NULL}
};

static PyMethodDef pyIRStmtExit_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IRStmtExit, IRStmt);
