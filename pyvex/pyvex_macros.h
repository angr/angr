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

// helper for type checking
#define PYVEX_CHECKTYPE(object, type, fail) if (!PyObject_TypeCheck((PyObject *)object, &type)) { PyErr_SetString(VexException, "Incorrect type passed in. Needs "#type); fail; }

// getter and setter definitions
#define PYVEX_ACCESSOR_DEF(type, attr) {#attr, (getter)py##type##_##get##_##attr, (setter)py##type##_##set##_##attr, #attr, NULL}

#define PYVEX_GETTER_BUILDVAL(type, intype, attr, name, format) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) \
	{ \
		PyObject *o = Py_BuildValue(format, self->attr); \
		if (!o) return NULL; \
		return o; \
	}
#define PYVEX_SETTER_BUILDVAL(type, intype, attr, name, format) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		if (!PyArg_Parse(value, format, &(self->attr))) return -1; \
		return 0; \
	}

#define PYVEX_GETTER_CAPSULE(type, intype, attr, name, ctype) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) { return PyCapsule_New(self->attr, #ctype, NULL); }
#define PYVEX_SETTER_CAPSULE(type, intype, attr, name, ctype) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		ctype *i = (ctype *)PyCapsule_GetPointer(value, #ctype); \
		if (i) { self->attr = i; return 0; } \
		else return -1; \
	}

#define PYVEX_GETTER_WRAPPED(type, intype, attr, name, attrtype) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) \
	{ \
		PyObject *o = wrap_##attrtype(self->attr); \
		return o; \
	}
#define PYVEX_SETTER_WRAPPED(type, intype, attr, name, attrtype) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		PYVEX_CHECKTYPE(value, py##attrtype##Type, return -1); \
		self->attr = ((py##attrtype *) value)->wrapped; \
		return 0; \
	}

#define PYVEX_SETTER(type, attr) PYVEX_SETTER_CAPSULE(type, type, attr, attr, type)
#define PYVEX_GETTER(type, attr) PYVEX_GETTER_CAPSULE(type, type, attr, attr, type)

// tag
#define PYVEX_GETTAG(type) \
	static PyObject *py##type##_get_tag(py##type *self, void *closure) \
	{ \
		const char *tstr = type##Tag_to_str(self->wrapped->tag); \
		if (tstr) return PyString_FromString(tstr); \
		PyErr_SetString(VexException, "Unrecognized tag."); \
		return NULL; \
	}
#define PYVEX_SETTAG(type) \
	static int py##type##_set_tag(py##type *self, PyObject *value, void *closure) \
	{ \
		const char *tstr = PyString_AsString(value); \
		type##Tag t = str_to_##type##Tag(tstr); \
		if (t) { self->wrapped->tag = t; return 0; } \
		else { PyErr_SetString(VexException, "Unrecognized tag."); return -1; } \
	}

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
		PyObject *o = PyObject_Call((PyObject *)&py##type##Type, args, kwargs); \
		Py_DECREF(args); \
		Py_DECREF(kwargs); \
		return (PyObject *)o; \
	}

// for the header
#define PYVEX_TYPEHEADER(type) \
	extern PyTypeObject py##type##Type; \
	PYVEX_STRUCT(type); \
	PyObject *wrap_##type(type *);

// type object
#define PYVEX_TYPEOBJECT(type) \
	PyTypeObject py##type##Type = \
	{ \
		PyObject_HEAD_INIT(NULL) \
		0,						/*ob_size*/ \
		"pyvex."#type,					/*tp_name*/ \
		sizeof(py##type),				/*tp_basicsize*/ \
		0,						/*tp_itemsize*/ \
		(destructor)py##type##_dealloc,			/*tp_dealloc*/ \
		0,						/*tp_print*/ \
		0,						/*tp_getattr*/ \
		0,						/*tp_setattr*/ \
		0,						/*tp_compare*/ \
		0,						/*tp_repr*/ \
		0,						/*tp_as_number*/ \
		0,						/*tp_as_sequence*/ \
		0,						/*tp_as_mapping*/ \
		0,						/*tp_hash */ \
		0,						/*tp_call*/ \
		0,						/*tp_str*/ \
		0,						/*tp_getattro*/ \
		0,						/*tp_setattro*/ \
		0,						/*tp_as_buffer*/ \
		Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/*tp_flags*/ \
		"Wrapped "#type" objects",		 	/* tp_doc */ \
		0,					 	/* tp_traverse */ \
		0,					 	/* tp_clear */ \
		0,					 	/* tp_richcompare */ \
		0,					 	/* tp_weaklistoffset */ \
		0,					 	/* tp_iter */ \
		0,					 	/* tp_iternext */ \
		py##type##_methods,				/* tp_methods */ \
		py##type##_members,				/* tp_members */ \
		py##type##_getseters,				/* tp_getset */ \
		0,						/* tp_base */ \
		0,						/* tp_dict */ \
		0,						/* tp_descr_get */ \
		0,						/* tp_descr_set */ \
		0,						/* tp_dictoffset */ \
		(initproc)py##type##_init,	  		/* tp_init */ \
		0,						/* tp_alloc */ \
		py##type##_new,					/* tp_new */ \
	};

#define PYVEX_SUBTYPEOBJECT(type, base) \
	typedef struct { py##base base; } py##type; \
	PyTypeObject py##type##Type = \
	{ \
		PyObject_HEAD_INIT(NULL) \
		0,						/*ob_size*/ \
		"pyvex."#type,					/*tp_name*/ \
		sizeof(py##type),				/*tp_basicsize*/ \
		0,						/*tp_itemsize*/ \
		0,						/*tp_dealloc*/ \
		0,						/*tp_print*/ \
		0,						/*tp_getattr*/ \
		0,						/*tp_setattr*/ \
		0,						/*tp_compare*/ \
		0,						/*tp_repr*/ \
		0,						/*tp_as_number*/ \
		0,						/*tp_as_sequence*/ \
		0,						/*tp_as_mapping*/ \
		0,						/*tp_hash */ \
		0,						/*tp_call*/ \
		0,						/*tp_str*/ \
		0,						/*tp_getattro*/ \
		0,						/*tp_setattro*/ \
		0,						/*tp_as_buffer*/ \
		Py_TPFLAGS_DEFAULT,				/*tp_flags*/ \
		"Wrapped "#type" objects",		 	/* tp_doc */ \
		0,					 	/* tp_traverse */ \
		0,					 	/* tp_clear */ \
		0,					 	/* tp_richcompare */ \
		0,					 	/* tp_weaklistoffset */ \
		0,					 	/* tp_iter */ \
		0,					 	/* tp_iternext */ \
		py##type##_methods,				/* tp_methods */ \
		0,						/* tp_members */ \
		py##type##_getseters,				/* tp_getset */ \
		&py##base##Type,					/* tp_base */ \
		0,						/* tp_dict */ \
		0,						/* tp_descr_get */ \
		0,						/* tp_descr_set */ \
		0,						/* tp_dictoffset */ \
		(initproc)py##type##_init,	  		/* tp_init */ \
		0,						/* tp_alloc */ \
		0,						/* tp_new */ \
	};

// enum conversion
#define PYVEX_ENUMCONV_TOSTRCASE(x) case x: return #x;
// TODO: make this faster
#define PYVEX_ENUMCONV_FROMSTR(x) if (strcmp(#x, s) == 0) { printf("Matched %s\n", s); return x; } else { printf("Not matched %s\n", s); }
#define PYVEX_WRAPCASE(vtype, tagtype, tag) case tagtype##_##tag: t = &py##vtype##tag##Type; break;

// type initialization
#define PYVEX_INITTYPE(type) \
	if (PyType_Ready(&py##type##Type) < 0) { fprintf(stderr, "py"#type"Type not ready...\n"); return; } \
	Py_INCREF(&py##type##Type); PyModule_AddObject(module, #type, (PyObject *)&py##type##Type);
