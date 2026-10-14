#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.analyses.decompiler.structured_codegen.c import CConstruct, CStatements
from angr.analyses.decompiler.structured_codegen.go import GoConstruct, GoStatements
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


def _addressless_statement_lists(root) -> list:
    """Statement lists without an address anywhere in a codegen tree."""
    out, seen, todo = [], set(), [root]
    while todo:
        node = todo.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, (list, tuple)):
            todo.extend(node)
            continue
        if not isinstance(node, (CConstruct, GoConstruct)):
            continue
        if isinstance(node, (CStatements, GoStatements)) and node.addr is None:
            out.append(node)
        for cls in type(node).__mro__:
            for slot in getattr(cls, "__slots__", ()):
                if slot not in ("codegen", "tags"):
                    todo.append(getattr(node, slot, None))
    return out


class TestCodegenStatementsAddr(unittest.TestCase):
    def _decompile(self, path, func_addr, flavor):
        # callees are not needed; expanding the Go call tree takes over a minute
        proj, cfg = load_project_with_scoped_cfg(path, func_addr, window=0x200, expand_call_tree=False)
        dec = proj.analyses.Decompiler(proj.kb.functions[func_addr], cfg=cfg.model, flavor=flavor)
        assert dec.codegen is not None and dec.codegen.cfunc is not None
        return dec.codegen

    def test_c_multi_statement_expression_has_addr(self):
        # sub_404230 renders a multi-statement expression, whose statement list used to have no address
        codegen = self._decompile(os.path.join(test_location, "x86_64", "true"), 0x404230, "pseudocode")
        assert not _addressless_statement_lists(codegen.cfunc)

    def test_go_rewritten_statements_have_addr(self):
        # Name.IsBlank wraps a single-statement body into a list and hoists a ternary into an if-else
        path = os.path.join(test_location, "x86_64", "go", "go1.22.5", "basics")
        codegen = self._decompile(path, 0x401840, "go")
        assert not _addressless_statement_lists(codegen.cfunc)


if __name__ == "__main__":
    unittest.main()
