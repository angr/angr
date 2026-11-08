from __future__ import annotations

import unittest

from archinfo import ArchAMD64

from angr.analyses.decompiler.struct_union import pointer_to_layout, union_pointer_struct_types
from angr.sim_type import SimTypeInt


class TestStructUnion(unittest.TestCase):
    def test_unaligned_offsets_survive_layout_construction_and_union(self):
        arch = ArchAMD64()
        int_ty = SimTypeInt().with_arch(arch)
        layouts = [pointer_to_layout({off: int_ty}, arch) for off in (1, 6)]
        for off, layout in zip((1, 6), layouts):
            assert layout.pts_to.offsets[f"field_{off:x}"] == off

        union = union_pointer_struct_types(layouts, arch)
        assert union is not None
        assert {name: off for name, off in union.pts_to.offsets.items() if not name.startswith("padding_")} == {
            "field_1": 1,
            "field_6": 6,
        }
        assert union.pts_to.size == 80


if __name__ == "__main__":
    unittest.main()
