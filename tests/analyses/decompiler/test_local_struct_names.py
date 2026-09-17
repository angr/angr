# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import re
import unittest

import archinfo

from angr.analyses.typehoon import typeconsts
from angr.analyses.typehoon.translator import TypeTranslator
from angr.sim_type import SimStruct, SimTypeInt, SimTypePointer
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestLocalStructNames(unittest.TestCase):
    """
    Structs inferred by Typehoon are named after the function they were inferred in (st_<addr>_<n>), so a struct that
    reaches a caller through a callee's prototype can never shadow a struct the caller inferred on its own.
    """

    def test_struct_names_carry_function_address_and_skip_known_structs(self):
        arch = archinfo.arch_from_id("amd64")
        tx = TypeTranslator(arch, func_addr=0x4008A0)
        assert tx.struct_name() == "st_4008a0_0"

        # lifting a prototype that carries a struct named like one of our own registers it as a known struct
        imported = SimStruct({"a": SimTypeInt()}, name="st_4008a0_1").with_arch(arch)
        tx.lift(SimTypePointer(imported).with_arch(arch))
        assert "st_4008a0_1" in tx.known_structs

        # a freshly inferred struct must not take the imported struct's name
        own, _ = tx.tc2simtype(typeconsts.Struct(fields={0: typeconsts.Int64()}))
        assert isinstance(own, SimStruct)
        assert own.name == "st_4008a0_2"
        assert own is not imported

        # without a function address the legacy naming scheme is kept
        assert TypeTranslator(arch).struct_name() == "struct_0"

    def test_imported_callee_struct_does_not_shadow_own_structs(self):
        bin_path = os.path.join(
            test_location,
            "x86_64",
            "windows",
            "2ac79168ca17bfdbf70b591dc681114afc29f09aba0df978c3a7db6ed69a3b59",
        )
        caller_addr, callee_addr = 0x18001BF38, 0x180059AD8
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, caller_addr, expand_call_tree=True, call_tree_depth=1, window=0x800
        )
        caller = proj.kb.functions[caller_addr]
        callee = proj.kb.functions[callee_addr]

        dec = proj.analyses.Decompiler(caller, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        own_defs = self._struct_defs(dec.codegen.text)
        assert set(own_defs) == {f"st_{caller_addr:x}_{i}" for i in range(3)}, sorted(own_defs)

        # decompiling the callees rewrites their prototypes with Typehoon-inferred types; one of them takes a pointer
        # to a struct inferred inside the callee
        for callee_addr_ in sorted(proj.kb.callgraph.successors(caller_addr)):
            f = proj.kb.functions[callee_addr_]
            if callee_addr_ == caller_addr or f.is_simprocedure or f.is_plt:
                continue
            proj.analyses.Decompiler(f, cfg=cfg.model)
        callee_struct_name = f"st_{callee_addr:x}_0"
        assert callee.prototype is not None and callee_struct_name in str(callee.prototype), str(callee.prototype)

        # the caller now imports the callee's struct through the call site. Before struct names carried the function
        # address, the imported struct_0 and the caller's own struct_0 collapsed into one typedef.
        dec2 = proj.analyses.Decompiler(caller, cfg=cfg.model, use_cache=False)
        assert dec2.codegen is not None and dec2.codegen.text is not None
        print_decompilation_result(dec2)
        text = dec2.codegen.text
        defs = self._struct_defs(text)
        assert set(own_defs) <= set(defs), f"own structs vanished: {set(own_defs) - set(defs)}"
        assert callee_struct_name in defs, f"the imported struct must keep its own name; got {sorted(defs)}"
        names = re.findall(r"typedef struct (\w+) \{", text)
        assert len(names) == len(set(names)), f"duplicate struct typedefs: {names}"
        referenced = set(re.findall(r"\bst_[0-9a-f]+_\d+\b", text))
        assert referenced <= set(defs), f"undefined structs referenced: {referenced - set(defs)}"

    @staticmethod
    def _struct_defs(text: str) -> dict[str, str]:
        return {
            name: re.sub(r"\s+", " ", body).strip()
            for name, body in re.findall(r"typedef struct (\w+) \{(.*?)\}", text, re.DOTALL)
        }


if __name__ == "__main__":
    unittest.main()
