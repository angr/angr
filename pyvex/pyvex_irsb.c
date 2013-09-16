#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "vex/angr_vexir.h"

PYVEX_NEW(IRSB)
PYVEX_DEALLOC(IRSB)
PYVEX_WRAP(IRSB)
PYVEX_METH_STANDARD(IRSB)

static int
pyIRSB_init(pyIRSB *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { self->wrapped = emptyIRSB(); return 0; }
	PYVEX_WRAP_CONSTRUCTOR(IRSB);

	PyObject *py_bytes = NULL;
	unsigned char *bytes = NULL;
	unsigned int mem_addr = 0;
	int num_inst = -1;
	int num_bytes = 0;

	static char *kwlist[] = {"wrap", "bytes", "mem_addr", "num_inst", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OSii", kwlist, &wrap_object, &py_bytes, &mem_addr, &num_inst)) return -1;

	if (py_bytes)
	{
		if (PyString_Size(py_bytes) == 0)
		{
			PyErr_SetString(VexException, "No bytes provided");
			return -1;
		}

		num_bytes = PyString_Size(py_bytes);
		bytes = (unsigned char *)PyString_AsString(py_bytes);

		vex_init();
		if (num_inst > -1) self->wrapped = vex_block_inst(VexArchAMD64, bytes, mem_addr, num_inst);
		else self->wrapped = vex_block_bytes(VexArchAMD64, bytes, mem_addr, num_bytes);
	}
	else
	{
		PyErr_SetString(VexException, "Not enough arguments provided.");
		return -1;
	}

	return 0;
}

static PyMemberDef pyIRSB_members[] =
{
	{NULL}  /* Sentinel */
};

PYVEX_SETTER(IRSB, wrapped)
PYVEX_GETTER(IRSB, wrapped)
PYVEX_SETTER_WRAPPED(IRSB, IRSB, wrapped->tyenv, tyenv, IRTypeEnv)
PYVEX_GETTER_WRAPPED(IRSB, IRSB, wrapped->tyenv, tyenv, IRTypeEnv)
PYVEX_SETTER_WRAPPED(IRSB, IRSB, wrapped->next, next, IRExpr)
PYVEX_GETTER_WRAPPED(IRSB, IRSB, wrapped->next, next, IRExpr)

static PyGetSetDef pyIRSB_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRSB, wrapped),
	PYVEX_ACCESSOR_DEF(IRSB, tyenv),
	PYVEX_ACCESSOR_DEF(IRSB, next),
	{NULL}  /* Sentinel */
};

static PyObject *
pyIRSB_statements(pyIRSB* self)
{
	PyObject *result = PyTuple_New(self->wrapped->stmts_used);

	for (int i = 0; i < self->wrapped->stmts_used; i++)
	{
		PyObject *wrapped = wrap_IRStmt(self->wrapped->stmts[i]);
		PyTuple_SetItem(result, i, wrapped);
	}

	return result;
}

static PyObject *pyIRSB_deepCopyExceptStmts(pyIRSB* self) { return (PyObject *)wrap_IRSB(deepCopyIRSBExceptStmts(self->wrapped)); }
static PyObject *pyIRSB_addStatement(pyIRSB* self, PyObject *stmt)
{
	PYVEX_CHECKTYPE(stmt, pyIRStmtType, return NULL);
	addStmtToIRSB(self->wrapped, ((pyIRStmt *)stmt)->wrapped);
	Py_RETURN_NONE;
}

static PyMethodDef pyIRSB_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRSB),
	{"addStatement", (PyCFunction)pyIRSB_addStatement, METH_O, "Adds a statement to the basic block."},
	{"deepCopyExceptStmts", (PyCFunction)pyIRSB_deepCopyExceptStmts, METH_NOARGS, "Copies the IRSB, without any statements."},
	{"statements", (PyCFunction)pyIRSB_statements, METH_NOARGS, "Returns a tuple of the IRStmts in the IRSB"},
	{NULL}  /* Sentinel */
};

PYVEX_TYPEOBJECT(IRSB);
