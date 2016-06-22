import nose

import simuvex
import claripy

def test_type_annotation():
    struct_ty = simuvex.s_type_backend.SimStructAbstract('mystruct')
    ptr = claripy.BVS('ptr', 32).annotate(simuvex.s_type_backend.TypeAnnotation(simuvex.s_type.SimTypePointer(struct_ty)))
    ptroffset = ptr + 4

    bt = simuvex.s_type_backend.TypeBackend()
    tv = bt.convert(ptroffset)
    nose.tools.assert_equal(tv.ty.pts_to.label, 'mystruct')
    nose.tools.assert_true(claripy.is_true(tv.ty.offset == 4))

if __name__ == '__main__':
    test_type_annotation()
