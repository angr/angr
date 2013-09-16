#ifndef __MACROS_H
#define __MACROS_H

// define the struct
#define PYVEX_STRUCT(type) typedef struct { PyObject_HEAD type *wrapped; } py##type;

// default allocation and deallocation
#define PYVEX_NEW(type) \
	static PyObject * \
	py##type##_new(PyTypeObject *type, PyObject *args, PyObject *kwds) \
  	{ \
  		py##type *self; \
		self = (py##type *)type->tp_alloc(type, 0); \
		if (self != NULL) self->wrapped = NULL; \
		return (PyObject *)self; \
	}
#define PYVEX_DEALLOC(type) static void py##type##_dealloc(py##type* self) { self->ob_type->tp_free((PyObject*)self); }

// Method definitions for Python's list
#define PYVEX_METHDEF_PP(type) {"pp", (PyCFunction)py##type##_pp, METH_NOARGS, "Prints the "#type}
#define PYVEX_METHDEF_DEEPCOPY(type) {"deepCopy", (PyCFunction)py##type##_deepCopy, METH_NOARGS, "Deep-copies the "#type}
#define PYVEX_METHDEF_STANDARD(type) PYVEX_METHDEF_PP(type), PYVEX_METHDEF_DEEPCOPY(type)

// The methods themselves
#define PYVEX_METH_PP(type) static PyObject * py##type##_pp(py##type* self) { pp##type(self->wrapped); Py_RETURN_NONE; }
#define PYVEX_METH_DEEPCOPY(type) \
	static PyObject * py##type##_deepCopy(py##type* self) { return (PyObject *)wrap_##type(deepCopy##type(self->wrapped)); }
#define PYVEX_METH_STANDARD(type) PYVEX_METH_PP(type) PYVEX_METH_DEEPCOPY(type)

// getter and setter definitions
#define PYVEX_ACCESSOR_DEF(type, attr) {#attr, (getter)py##type##_##get##_##attr, (setter)py##type##_##set##_##attr, #attr, NULL}
#define PYVEX_ACCESSOR_DEF_WRAPPED(type) PYVEX_ACCESSOR_DEF(type, wrapped)
#define PYVEX_ACCESSOR_SET_WRAPPED(type) \
	static int py##type##_set_wrapped(py##type *self, PyObject *value, void *closure) \
	{ \
		type *wrapped = PyCapsule_GetPointer(value, #type); \
		if (wrapped) { self->wrapped = wrapped; return 0; } \
		else return -1; \
	}
#define PYVEX_ACCESSOR_GET_WRAPPED(type) \
	static PyObject *py##type##_get_wrapped(py##type *self, void *closure) { return PyCapsule_New(self->wrapped, #type, NULL); }

// wrapping constructor
#define PYVEX_WRAP_CONSTRUCTOR(type) \
	PyObject *wrap_object; \
	if (kwargs) \
	{ \
		wrap_object = PyDict_GetItemString(kwargs, "wrap"); \
		if (wrap_object) \
		{ \
			self->wrapped = PyCapsule_GetPointer(wrap_object, #type); \
			if (!self->wrapped) return -1; \
			return 0; \
		} \
	}

#endif

// wrapping helper
#define PYVEX_WRAP(type) \
	PyObject *wrap_##type(type *i) \
	{ \
		PyObject *args = Py_BuildValue(""); \
		PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, #type, NULL)); \
		py##type *o = (py##type *)PyObject_Call((PyObject *)&py##type##Type, args, kwargs); \
		Py_DECREF(args); \
		Py_DECREF(kwargs); \
		return (PyObject *)o; \
	}
