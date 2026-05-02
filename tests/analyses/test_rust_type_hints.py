from __future__ import annotations

from collections import OrderedDict

import angr
import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.rust.sim_type import RustSimStruct, RustSimTypeInt


def test_rust_type_hints_are_function_scoped():
    project = angr.load_shellcode(b"\xc3", arch="amd64")
    vvar = VirtualVariable(0, 7, 64, VirtualVariableCategory.REGISTER, 0)

    ty_a = RustSimStruct(OrderedDict({"field_0": RustSimTypeInt(64, signed=False)}), name="TypeA", pack=True).with_arch(
        project.arch
    )
    ty_b = RustSimStruct(OrderedDict({"field_0": RustSimTypeInt(32, signed=False)}), name="TypeB", pack=True).with_arch(
        project.arch
    )

    project.kb.type_hints.add_type_hint(vvar, ty_a, 0x1000)
    project.kb.type_hints.add_type_hint(vvar, ty_b, 0x2000)

    with pytest.raises(TypeError):
        project.kb.type_hints.add_type_hint(vvar, ty_a)

    assert project.kb.type_hints.get_type_hints(0x1000)[vvar.varid].name == "TypeA"
    assert project.kb.type_hints.get_type_hints(0x2000)[vvar.varid].name == "TypeB"
    assert vvar.varid not in project.kb.type_hints.get_type_hints(0x3000)
