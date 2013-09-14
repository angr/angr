#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "vex/angr_vexir.h"

typedef struct {
	PyObject_HEAD
	PyObject *first;
	PyObject *last;
	int number;
} pyIRSB;

static void
pyIRSB_dealloc(pyIRSB* self)
{
	Py_XDECREF(self->first);
	Py_XDECREF(self->last);
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
pyIRSB_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	pyIRSB *self;

	self = (pyIRSB *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->first = PyString_FromString("");
		if (self->first == NULL)
		  {
			Py_DECREF(self);
			return NULL;
		  }
		
		self->last = PyString_FromString("");
		if (self->last == NULL)
		  {
			Py_DECREF(self);
			return NULL;
		  }

		self->number = 0;
	}

	return (PyObject *)self;
}

static int
pyIRSB_init(pyIRSB *self, PyObject *args, PyObject *kwds)
{
	PyObject *first=NULL, *last=NULL, *tmp;

	static char *kwlist[] = {"first", "last", "number", NULL};

	if (! PyArg_ParseTupleAndKeywords(args, kwds, "|SSi", kwlist, 
									  &first, &last, 
									  &self->number))
		return -1; 

	if (first) {
		tmp = self->first;
		Py_INCREF(first);
		self->first = first;
		Py_DECREF(tmp);
	}

	if (last) {
		tmp = self->last;
		Py_INCREF(last);
		self->last = last;
		Py_DECREF(tmp);
	}

	return 0;
}

static PyMemberDef pyIRSB_members[] = {
	{"number", T_INT, offsetof(pyIRSB, number), 0,
	 "pyvex number"},
	{NULL}  /* Sentinel */
};

static PyObject *
pyIRSB_getfirst(pyIRSB *self, void *closure)
{
	Py_INCREF(self->first);
	return self->first;
}

static int
pyIRSB_setfirst(pyIRSB *self, PyObject *value, void *closure)
{
  if (value == NULL) {
	PyErr_SetString(PyExc_TypeError, "Cannot delete the first attribute");
	return -1;
  }
  
  if (! PyString_Check(value)) {
	PyErr_SetString(PyExc_TypeError, 
					"The first attribute value must be a string");
	return -1;
  }
	  
  Py_DECREF(self->first);
  Py_INCREF(value);
  self->first = value;	

  return 0;
}

static PyObject *
pyIRSB_getlast(pyIRSB *self, void *closure)
{
	Py_INCREF(self->last);
	return self->last;
}

static int
pyIRSB_setlast(pyIRSB *self, PyObject *value, void *closure)
{
  if (value == NULL) {
	PyErr_SetString(PyExc_TypeError, "Cannot delete the last attribute");
	return -1;
  }
  
  if (! PyString_Check(value)) {
	PyErr_SetString(PyExc_TypeError, 
					"The last attribute value must be a string");
	return -1;
  }
	  
  Py_DECREF(self->last);
  Py_INCREF(value);
  self->last = value;	

  return 0;
}

static PyGetSetDef pyIRSB_getseters[] = {
	{"first", 
	 (getter)pyIRSB_getfirst, (setter)pyIRSB_setfirst,
	 "first name",
	 NULL},
	{"last", 
	 (getter)pyIRSB_getlast, (setter)pyIRSB_setlast,
	 "last name",
	 NULL},
	{NULL}  /* Sentinel */
};

static PyObject *
pyIRSB_name(pyIRSB* self)
{
	static PyObject *format = NULL;
	PyObject *args, *result;

	if (format == NULL) {
		format = PyString_FromString("%s %s");
		if (format == NULL)
			return NULL;
	}

	args = Py_BuildValue("OO", self->first, self->last);
	if (args == NULL)
		return NULL;

	result = PyString_Format(format, args);
	Py_DECREF(args);
	
	return result;
}

static PyMethodDef pyIRSB_methods[] = {
	{"name", (PyCFunction)pyIRSB_name, METH_NOARGS,
	 "Return the name, combining the first and last name"
	},
	{NULL}  /* Sentinel */
};

static PyTypeObject pyIRSBType = {
	PyObject_HEAD_INIT(NULL)
	0,						 /*ob_size*/
	"pyvex.IRSB",			 /*tp_name*/
	sizeof(pyIRSB),			 /*tp_basicsize*/
	0,						 /*tp_itemsize*/
	(destructor)pyIRSB_dealloc, /*tp_dealloc*/
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
	"pyIRSB objects",		   /* tp_doc */
	0,					   /* tp_traverse */
	0,					   /* tp_clear */
	0,					   /* tp_richcompare */
	0,					   /* tp_weaklistoffset */
	0,					   /* tp_iter */
	0,					   /* tp_iternext */
	pyIRSB_methods,			 /* tp_methods */
	pyIRSB_members,			 /* tp_members */
	pyIRSB_getseters,		   /* tp_getset */
	0,						 /* tp_base */
	0,						 /* tp_dict */
	0,						 /* tp_descr_get */
	0,						 /* tp_descr_set */
	0,						 /* tp_dictoffset */
	(initproc)pyIRSB_init,	  /* tp_init */
	0,						 /* tp_alloc */
	pyIRSB_new,				 /* tp_new */
};
