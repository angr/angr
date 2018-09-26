import claripy

from .sim_type import SimTypePointer as Ptr, SimTypeTop as Top

class TypedValue(claripy.BackendObject):
    def __init__(self, ty, value):
        self.ty = ty
        self.value = value

    def __repr__(self):
        return 'TypedValue(%s, %s)' % (repr(self.ty), repr(self.value))

class TypeBackend(claripy.Backend):
    def __init__(self):
        super(TypeBackend, self).__init__(solver_required=False)

        self._op_expr['BVS'] = self._make_top
        self._op_expr['BVV'] = self._make_top

        self._op_raw['__add__'] = self._do_add
        self._op_raw['__sub__'] = self._do_sub
        self._op_raw['__and__'] = self._do_and
        self._op_raw['__or__'] = self._do_or
        self._op_raw['__xor__'] = self._do_xor

    @staticmethod
    def _make_top(ast, **kwargs):   # pylint: disable=unused-argument
        return TypedValue(Top(label=[]), ast)

    def _do_add(self, *args):
        if len(args) != 2:
            return reduce(self._do_add, args)

        a, b = args
        good_a = type(a.ty) is Ptr
        good_b = type(b.ty) is Ptr
        val = a.value + b.value
        out = TypedValue(Top(), val)

        if good_a:
            if not good_b:
                out.ty = Ptr(a.ty.pts_to, offset=a.ty.offset + b.value)
        elif good_b:
            out.ty = Ptr(b.ty.pts_to, offset=b.ty.offset + a.value)
        else:
            out.ty = Top()

        out.ty.label = a.ty.label + b.ty.label
        return out

    def _do_and(self, *args):
        if len(args) != 2:
            return reduce(self._do_and, args)

        a, b = args
        good_a = type(a.ty) is Ptr
        good_b = type(b.ty) is Ptr
        val = a.value & b.value
        out = TypedValue(Top(), val)

        if good_a:
            if not good_b:
                out.ty = Ptr(a.ty.pts_to, offset=a.ty.offset & b.value)
        elif good_b:
            out.ty = Ptr(b.ty.pts_to, offset=b.ty.offset & a.value)
        else:
            out.ty = Top()

        out.ty.label = a.ty.label + b.ty.label
        return out

    def _do_or(self, *args):
        if len(args) != 2:
            return reduce(self._do_or, args)

        a, b = args
        good_a = type(a.ty) is Ptr
        good_b = type(b.ty) is Ptr
        val = a.value | b.value
        out = TypedValue(Top(), val)

        if good_a:
            if not good_b:
                out.ty = Ptr(a.ty.pts_to, offset=a.ty.offset | b.value)
        elif good_b:
            out.ty = Ptr(b.ty.pts_to, offset=b.ty.offset | a.value)
        else:
            out.ty = Top(label=[])

        out.ty.label = a.ty.label + b.ty.label
        return out

    def _do_xor(self, *args):
        if len(args) != 2:
            return reduce(self._do_xor, args)

        a, b = args
        good_a = type(a.ty) is Ptr
        good_b = type(b.ty) is Ptr
        val = a.value ^ b.value
        out = TypedValue(Top(), val)

        if good_a:
            if not good_b:
                out.ty = Ptr(a.ty.pts_to, offset=a.ty.offset ^ b.value)
        elif good_b:
            out.ty = Ptr(b.ty.pts_to, offset=b.ty.offset ^ a.value)
        else:
            out.ty = Top()

        out.ty.label = a.ty.label + b.ty.label
        return out

    def _do_sub(self, *args):
        if len(args) != 2:
            return reduce(self._do_sub, args)

        a, b = args
        good_a = type(a.ty) is Ptr
        good_b = type(b.ty) is Ptr
        val = a.value - b.value
        out = TypedValue(Top(None), val)

        if good_a and not good_b:
            out.ty = Ptr(a.ty.pts_to, offset=a.ty.offset - b.value)
        else:
            out.ty = Top()

        out.ty.label = a.ty.label + b.ty.label
        return out

    def apply_annotation(self, obj, a):
        if type(a) is TypeAnnotation:
            return TypedValue(a.ty, obj.value)
        return obj

    @staticmethod
    def default_op(expr):
        return TypedValue(Top(label=[]), expr)

class TypeAnnotation(claripy.Annotation):
    def __init__(self, ty):
        self.ty = ty

    @property
    def eliminatable(self): #pylint:disable=no-self-use
        return False

    @property
    def relocatable(self): #pylint:disable=no-self-use
        return False
