import nose

import angr
import claripy

def test_type_annotation():
    my_ty = angr.sim_type.SimTypeTop()
    ptr = claripy.BVS('ptr', 32).annotate(angr.type_backend.TypeAnnotation(angr.sim_type.SimTypePointer(my_ty, label=[])))
    ptroffset = ptr + 4

    bt = angr.type_backend.TypeBackend()
    tv = bt.convert(ptroffset)
    nose.tools.assert_is(tv.ty.pts_to, my_ty)
    nose.tools.assert_true(claripy.is_true(tv.ty.offset == 4))

if __name__ == '__main__':
    test_type_annotation()
