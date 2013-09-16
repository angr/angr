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

PYVEX_ACCESSOR_SET_WRAPPED(IRStmt)
PYVEX_ACCESSOR_GET_WRAPPED(IRStmt)

static PyGetSetDef pyIRStmt_getseters[] =
{
	PYVEX_ACCESSOR_DEF_WRAPPED(IRStmt),
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

PyTypeObject pyIRStmtType =
{
	PyObject_HEAD_INIT(NULL)
	0,						 /*ob_size*/
	"pyvex.IRStmt",			 /*tp_name*/
	sizeof(pyIRStmt),			 /*tp_basicsize*/
	0,						 /*tp_itemsize*/
	(destructor)pyIRStmt_dealloc, /*tp_dealloc*/
	0,						 /*tp_print*/
	0,						 /*tp_getattr*/
	0,						 /*tp_setattr*/
	0,						 /*tp_compare*/
	0,						 /*tp_repr*/
	0,						 /*tp_as_number*/
	0,						 /*tp_as_sequence*/
	0,						 /*tp_as_mapping*/
	0,						 /*tp_hash */
	0,						 /*tp_call*/
	0,						 /*tp_str*/
	0,						 /*tp_getattro*/
	0,						 /*tp_setattro*/
	0,						 /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	"pyIRStmt objects",		   /* tp_doc */
	0,					   /* tp_traverse */
	0,					   /* tp_clear */
	0,					   /* tp_richcompare */
	0,					   /* tp_weaklistoffset */
	0,					   /* tp_iter */
	0,					   /* tp_iternext */
	pyIRStmt_methods,			 /* tp_methods */
	pyIRStmt_members,			 /* tp_members */
	pyIRStmt_getseters,		   /* tp_getset */
	0,						 /* tp_base */
	0,						 /* tp_dict */
	0,						 /* tp_descr_get */
	0,						 /* tp_descr_set */
	0,						 /* tp_dictoffset */
	(initproc)pyIRStmt_init,	  /* tp_init */
	0,						 /* tp_alloc */
	pyIRStmt_new,				 /* tp_new */
};
