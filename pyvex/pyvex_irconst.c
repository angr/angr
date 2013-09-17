#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"

////////////////////////
// IRConst base class //
////////////////////////

PYVEX_NEW(IRConst)
PYVEX_DEALLOC(IRConst)
PYVEX_METH_STANDARD(IRConst)

static int
pyIRConst_init(pyIRConst *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRConst);
	PyErr_SetString(VexException, "Base IRConst creation not supported.");
	return -1;
}

PYVEX_SETTER(IRConst, wrapped)
PYVEX_GETTER(IRConst, wrapped)
PYVEX_ACCESSOR_ENUM(IRConst, IRConst, IRConstTag, wrapped->tag, tag)

static PyGetSetDef pyIRConst_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRConst, tag),
	PYVEX_ACCESSOR_DEF(IRConst, wrapped),
	{NULL}
};

static PyMethodDef pyIRConst_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRConst),
	{NULL}
};

static PyMemberDef pyIRConst_members[] = { {NULL} };
PYVEX_TYPEOBJECT(IRConst);

//////////////////////
// IRConst wrapping //
//////////////////////

PyObject *wrap_IRConst(IRConst *i)
{
	PyTypeObject *t = NULL;

	switch (i->tag)
	{
		PYVEX_WRAPCASE(IRConst, Ico_, U1)
		PYVEX_WRAPCASE(IRConst, Ico_, U8)
		PYVEX_WRAPCASE(IRConst, Ico_, U16)
		PYVEX_WRAPCASE(IRConst, Ico_, U32)
		PYVEX_WRAPCASE(IRConst, Ico_, U64)
		PYVEX_WRAPCASE(IRConst, Ico_, F32)
		PYVEX_WRAPCASE(IRConst, Ico_, F32i)
		PYVEX_WRAPCASE(IRConst, Ico_, F64)
		PYVEX_WRAPCASE(IRConst, Ico_, F64i)
		PYVEX_WRAPCASE(IRConst, Ico_, V128)
		PYVEX_WRAPCASE(IRConst, Ico_, V256)
		default:
			fprintf(stderr, "PyVEX: Unknown/unsupported IRConstTag %s\n", IRConstTag_to_str(i->tag));
			t = &pyIRStmtType;
	}

	PyObject *args = Py_BuildValue("");
	PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, "IRConst", NULL));
	PyObject *o = PyObject_Call((PyObject *)t, args, kwargs);
	Py_DECREF(args); Py_DECREF(kwargs);
	return (PyObject *)o;
}

////////////////////
// Constant types //
////////////////////

#define PYVEX_IRCONST_SUBCLASS(tag, type, format) \
	int pyIRConst##tag##_init(pyIRConst *self, PyObject *args, PyObject *kwargs) \
	{ \
		PYVEX_WRAP_CONSTRUCTOR(IRConst); \
	 \
		type value; \
		static char *kwlist[] = {"value", "wrap", NULL}; \
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, format"|O", kwlist, &value, &wrap_object)) return -1; \
		self->wrapped = IRConst_##tag(value); \
		return 0; \
	} \
	 \
	PYVEX_ACCESSOR_BUILDVAL(IRConst##tag, IRConst, wrapped->Ico.tag, value, format) \
	 \
	PyGetSetDef pyIRConst##tag##_getseters[] = \
	{ \
		PYVEX_ACCESSOR_DEF(IRConst##tag, value), \
		{NULL} \
	}; \
	 \
	PyMethodDef pyIRConst##tag##_methods[] = { {NULL} }; \
	PYVEX_SUBTYPEOBJECT(IRConst##tag, IRConst); \

PYVEX_IRCONST_SUBCLASS(U1, unsigned char, "b");
PYVEX_IRCONST_SUBCLASS(U8, unsigned char, "b");
PYVEX_IRCONST_SUBCLASS(U16, unsigned short int, "H");
PYVEX_IRCONST_SUBCLASS(U32, unsigned int, "I");
PYVEX_IRCONST_SUBCLASS(U64, unsigned long long, "K");
PYVEX_IRCONST_SUBCLASS(F32, float, "f");
PYVEX_IRCONST_SUBCLASS(F32i, unsigned int, "I");
PYVEX_IRCONST_SUBCLASS(F64, double, "d");
PYVEX_IRCONST_SUBCLASS(F64i, unsigned long long, "K");
PYVEX_IRCONST_SUBCLASS(V128, unsigned short int, "H");
PYVEX_IRCONST_SUBCLASS(V256, unsigned int, "I");

//int pyIRConst_set_value(pyIRConst *self, PyObject *v, void *closure)
//{
//	unsigned long long i;
//	float f;
//	double d;
//
//	switch (self->wrapped->tag)
//	{
//		case Ico_U1:
//		case Ico_U8:
//		case Ico_U16:
//		case Ico_U32:
//		case Ico_U64:
//		case Ico_F32i:
//		case Ico_F64i:
//			i = PyLong_AsUnsignedLongLong(v);
//			if (PyErr_Occurred()) return -1;
//
//			switch (self->wrapped->tag)
//			{
//				case Ico_U1:
//					if (i > 1) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.U1 = (Bool) i;
//					return 0;
//				case Ico_U8:
//					if (i > 255) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.U8 = (Bool) i;
//					return 0;
//				case Ico_U16:
//					if (i > 65535) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.U16 = (UShort) i;
//					return 0;
//				case Ico_V128:
//					if (i > 65535) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.V128 = (UShort) i;
//					return 0;
//				case Ico_U32:
//					if (i > 4294967295) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.U32 = (UInt) i;
//					return 0;
//				case Ico_F32i:
//					if (i > 4294967295) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.F32i = (UInt) i;
//					return 0;
//				case Ico_V256:
//					if (i > 4294967295) { PyErr_SetString(VexException, "Val out of range for constant type"); return -1; }
//					self->wrapped->Ico.V256 = (UInt) i;
//					return 0;
//				case Ico_U64:
//					self->wrapped->Ico.U64 = (ULong) i;
//					return 0;
//				case Ico_F64i:
//					self->wrapped->Ico.F64i = (ULong) i;
//					return 0;
//				default:
//					break;
//			}
//		case Ico_F32:
//			f = PyFloat_AsDouble(v);
//			if (PyErr_Occurred()) return -1;
//			self->wrapped->Ico.F32 = (Float) f;
//			return 0;
//		case Ico_F64:
//			d = PyFloat_AsDouble(v);
//			if (PyErr_Occurred()) return -1;
//			self->wrapped->Ico.F64 = (Double) d;
//			return 0;
//			PyErr_SetString(VexException, "Constant type V128 is not implemented");
//			return -1;
//		default:
//			PyErr_SetString(VexException, "Unexpected constant type in pyIRConst_set_value.");
//			return -1;
//	}
//}
//
//PyObject *pyIRConst_get_value(pyIRConst *self, PyObject *v, void *closure)
//{
//	switch (self->wrapped->tag)
//	{
//		case Ico_U1:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.U1);
//		case Ico_U8:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.U8);
//		case Ico_U16:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.U16);
//		case Ico_U32:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.U32);
//		case Ico_U64:
//			return PyLong_FromUnsignedLongLong(self->wrapped->Ico.U64);
//		case Ico_F32i:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.F32i);
//		case Ico_F64i:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.F64i);
//		case Ico_F32:
//			return PyFloat_FromDouble(self->wrapped->Ico.F32);
//		case Ico_F64:
//			return PyFloat_FromDouble(self->wrapped->Ico.F64);
//		case Ico_V128:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.V128);
//		case Ico_V256:
//			return PyLong_FromUnsignedLong(self->wrapped->Ico.V256);
//		default:
//			PyErr_SetString(VexException, "Unexpected constant type in pyIRConst_get_value.");
//			return NULL;
//	}
//}
