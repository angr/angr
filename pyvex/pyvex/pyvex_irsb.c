#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "pyvex_vexir.h"

PYVEX_NEW(IRSB)
PYVEX_DEALLOC(IRSB)
PYVEX_WRAP(IRSB)
PYVEX_METH_STANDARD(IRSB)

static int
pyIRSB_init(pyIRSB *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { self->wrapped = emptyIRSB(); return 0; }
	PYVEX_WRAP_CONSTRUCTOR(IRSB);

	unsigned char *bytes = NULL;
	unsigned int mem_addr = 0;
	int num_inst = -1;
	int num_bytes = -1;

	static char *kwlist[] = {"bytes", "mem_addr", "num_inst", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s#ii", kwlist, &bytes, &num_bytes, &mem_addr, &num_inst)) return -1;

	if (num_bytes == 0)
	{
		PyErr_SetString(VexException, "No bytes provided");
		return -1;
	}

	if (num_bytes > 0)
	{
		vex_init();
		if (num_inst > -1) self->wrapped = vex_block_inst(VexArchAMD64, bytes, mem_addr, num_inst);
		else self->wrapped = vex_block_bytes(VexArchAMD64, bytes, mem_addr, num_bytes);

		if (self->wrapped == NULL) { PyErr_SetString(VexException, "Error creating IR."); return -1; }
		return 0;
	}

	PyErr_SetString(VexException, "Not enough arguments provided.");
	return -1;
}

static PyMemberDef pyIRSB_members[] = { {NULL} };

PYVEX_SETTER(IRSB, wrapped)
PYVEX_GETTER(IRSB, wrapped)
PYVEX_ACCESSOR_WRAPPED(IRSB, IRSB, wrapped->tyenv, tyenv, IRTypeEnv)
PYVEX_ACCESSOR_WRAPPED(IRSB, IRSB, wrapped->next, next, IRExpr)
PYVEX_ACCESSOR_ENUM(IRSB, IRSB, wrapped->jumpkind, jumpkind, IRJumpKind)
PYVEX_ACCESSOR_BUILDVAL(IRSB, IRSB, wrapped->offsIP, offsIP, "i")

static PyGetSetDef pyIRSB_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRSB, wrapped),
	PYVEX_ACCESSOR_DEF(IRSB, tyenv),
	PYVEX_ACCESSOR_DEF(IRSB, next),
	PYVEX_ACCESSOR_DEF(IRSB, jumpkind),
	PYVEX_ACCESSOR_DEF(IRSB, offsIP),
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

static PyObject *pyIRSB_instructions(pyIRSB *self)
{
	long instructions = 0;
	for (int i = 0; i < self->wrapped->stmts_used; i++)
	{
		if (self->wrapped->stmts[i]->tag == Ist_IMark) instructions++;
	}

	return PyInt_FromLong(instructions);
}
static PyObject *pyIRSB_size(pyIRSB *self)
{
	long size = 0;
	for (int i = 0; i < self->wrapped->stmts_used; i++)
	{
		if (self->wrapped->stmts[i]->tag == Ist_IMark) size += self->wrapped->stmts[i]->Ist.IMark.len;
	}

	return PyInt_FromLong(size);
}

static PyMethodDef pyIRSB_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRSB),
	{"addStatement", (PyCFunction)pyIRSB_addStatement, METH_O, "Adds a statement to the basic block."},
	{"deepCopyExceptStmts", (PyCFunction)pyIRSB_deepCopyExceptStmts, METH_NOARGS, "Copies the IRSB, without any statements."},
	{"statements", (PyCFunction)pyIRSB_statements, METH_NOARGS, "Returns a tuple of the IRStmts in the IRSB"},
	{"instructions", (PyCFunction)pyIRSB_instructions, METH_NOARGS, "Returns the number of host instructions in the IRSB"},
	{"size", (PyCFunction)pyIRSB_size, METH_NOARGS, "Returns the size, in bytes, of the host instructions represented by the IRSB"},
	{NULL}  /* Sentinel */
};

PYVEX_TYPEOBJECT(IRSB);
