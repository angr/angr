# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.knowledge_plugins.functions import Function
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _function_reference_names(codegen):
    """The Function reference values of every CConstant the renderer emitted, read out of its position map."""
    names, seen = [], set()
    for elem in (codegen.map_pos_to_node or {}).values():
        obj = getattr(elem, "obj", None)
        if not isinstance(obj, CConstant) or id(obj) in seen or not obj.reference_values:
            continue
        seen.add(id(obj))
        names += [v.name for v in obj.reference_values.values() if isinstance(v, Function)]
    return sorted(names)


class TestCConstFunctionReference(TestCase):
    def test_cached_function_pointer_constant_rerenders_as_a_name(self):
        # _handle_Expr_Const stores a Function in CConstant.reference_values for a function-pointer constant, so
        # _start's call to __libc_start_main renders its callbacks by name. The cache has to carry that Function:
        # without it the constant re-renders through hex(), turning each name back into a bare address.
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        func = cfg.functions["_start"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, update_cache=True)
        assert dec.codegen is not None and dec.cache is not None
        before = dec.codegen.text
        assert before is not None
        assert "__libc_start_main(main, " in before
        assert _function_reference_names(dec.codegen) == ["__libc_csu_fini", "__libc_csu_init", "main"]

        back = DecompilationCache.parse(dec.cache.serialize(), project=proj, kb=proj.kb, function=func, cfg=cfg.model)
        assert back.codegen is not None
        assert back.codegen.text == before  # the stored text, restored from the blob
        back.codegen.regenerate_text()
        assert back.codegen.text == before  # and the re-render, which goes back through the reference values
        assert _function_reference_names(back.codegen) == ["__libc_csu_fini", "__libc_csu_init", "main"]


if __name__ == "__main__":
    main()
