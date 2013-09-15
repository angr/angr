#ifndef __MACROS_H
#define __MACROS_H

// default allocation and deallocation
#define PYVEX_NEW(type) \
	static PyObject * \
	py##type##_new(PyTypeObject *type, PyObject *args, PyObject *kwds) \
  	{ \
  		py##type *self; \
		self = (py##type *)type->tp_alloc(type, 0); \
		if (self != NULL) self->wrapped_##type = NULL; \
		return (PyObject *)self; \
	}
#define PYVEX_DEALLOC(type) static void py##type##_dealloc(py##type* self) { self->ob_type->tp_free((PyObject*)self); }

// define the struct
#define PYVEX_STRUCT(type) typedef struct { PyObject_HEAD type *wrapped_##type; } py##type;

// Method definitions for Python's list
#define PYVEX_METHDEF_PP(type) {"pp", (PyCFunction)py##type##_pp, METH_NOARGS, "Prints the "#type}
#define PYVEX_METHDEF_DEEPCOPY(type) {"deepCopy", (PyCFunction)py##type##_deepCopy, METH_NOARGS, "Deep-copies the "#type}
#define PYVEX_METHDEF_STANDARD(type) PYVEX_METHDEF_PP(type), PYVEX_METHDEF_DEEPCOPY(type)

// The methods themselves
#define PYVEX_METH_PP(type) static PyObject * py##type##_pp(py##type* self) { pp##type(self->wrapped_##type); Py_RETURN_NONE; }
#define PYVEX_METH_DEEPCOPY(type) \
	static PyObject * py##type##_deepCopy(py##type* self) \
	{ \
		py##type *o = (py##type *)PyObject_CallObject((PyObject *)&py##type##Type, NULL); \
		o->wrapped_##type = deepCopy##type(self->wrapped_##type); \
		return (PyObject *)o; \
	}
#define PYVEX_METH_STANDARD(type) PYVEX_METH_PP(type) PYVEX_METH_DEEPCOPY(type)

#endif
