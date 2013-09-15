#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_types.h"
#include "vex/angr_vexir.h"

//////////////////
// Python stuff //
//////////////////

typedef struct
{
	PyObject_HEAD
	IRStmt *irstmt;
} pyIRStmt;

static void
pyIRStmt_dealloc(pyIRStmt* self)
{
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
pyIRStmt_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	pyIRStmt *self;

	self = (pyIRStmt *)type->tp_alloc(type, 0);
	if (self != NULL) self->irstmt = NULL;

	return (PyObject *)self;
}

static int
pyIRStmt_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	// default constructor does nothing
	if ((!args || PyTuple_Size(args)) <= 0 && (!kwargs || PyDict_Size(kwargs) <= 0)) return 0;

	PyObject *tag = NULL;
	static char *kwlist[] = {"tag", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|S", kwlist, &tag))
		return -1;

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
	{NULL}  /* Sentinel */
}; 
static PyGetSetDef pyIRStmt_getseters[] =
{
	{NULL}  /* Sentinel */
};

static PyObject *
pyIRStmt_pp(pyIRStmt* self)
{
	ppIRStmt(self->irstmt);
	Py_RETURN_NONE;
}

static PyMethodDef pyIRStmt_methods[] =
{
	{"pp", (PyCFunction)pyIRStmt_pp, METH_NOARGS, "Prints the IRStmt"},
	{NULL}  /* Sentinel */
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

/////////////////
// Other stuff //
/////////////////

PyObject *wrap_stmt(IRStmt *i)
{
	//PyObject *stmt_type = PyObject_GetAttrString(module, "IRStmt");
	//pyIRStmt *stmt = (pyIRStmt *)PyObject_CallObject(stmt_type, NULL);
	//Py_DECREF(stmt_type);

	//PyObject *args = Py_BuildValue("()");
	//pyIRStmt *stmt = (pyIRStmt *)PyObject_Call((PyObject *)&pyIRStmtType, args, NULL);
	//Py_DECREF(args);

	pyIRStmt *stmt = (pyIRStmt *)PyObject_CallObject((PyObject *)&pyIRStmtType, NULL);

	//PyObject *pdict = PyModule_GetDict(module);
	//if (pdict == NULL) printf("Can't get module dict\n");
	//pyIRStmt *stmt = (pyIRStmt *)PyRun_String("IRStmt()", Py_single_input, pdict, pdict);
	//if (stmt == NULL) printf("Error while running string\n");

	stmt->irstmt = i;

	return (PyObject *)stmt;
}
