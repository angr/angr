#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

GOTO_RE = re.compile(r"goto\s+(LABEL_[0-9a-fA-Fx]+)\s*;")
LABEL_RE = re.compile(r"^\s*(LABEL_[0-9a-fA-Fx]+)\s*:", re.MULTILINE)
RETURN_RE = re.compile(r"^return\b")


class TestPhoenixResidualLabels(unittest.TestCase):
    """
    When structuring gives up, the residual region can only be laid out as one sequence if every node in it is
    still reachable afterwards: a node that is not the fall-through of the one in front of it has to be entered
    by a goto that names it. c_isxdigit is a region where that does not hold -- its jump-table successors are
    reached through a computed target, so nothing names them -- and concatenating it emits returns that no
    label and no fall-through can reach.
    """

    @staticmethod
    def _decompile(bin_path, func_addr):
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True)
        dec = proj.analyses.Decompiler(func_addr, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec.codegen.text

    @staticmethod
    def _dangling_gotos(text: str) -> list[str]:
        return sorted(set(GOTO_RE.findall(text)) - set(LABEL_RE.findall(text)))

    @staticmethod
    def _unreachable_statements(text: str) -> list[str]:
        """
        Statements laid out behind a return at the same nesting depth, with no label in between: nothing can
        fall into them and nothing names them.
        """
        found = []
        returned_at: int | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped in ("{", "}"):
                continue
            indent = len(line) - len(line.lstrip())
            if LABEL_RE.match(line):
                returned_at = None
                continue
            if returned_at is not None and indent <= returned_at:
                found.append(stripped)
                returned_at = None
            if RETURN_RE.match(stripped):
                returned_at = indent
        return found

    def test_c_isxdigit_residual_is_not_concatenated_without_labels(self):
        bin_path = os.path.join(test_location, "armel", "decompiler", "rm")
        text = self._decompile(bin_path, 0x17618)

        assert not self._dangling_gotos(text), f"goto without a label in:\n{text}"
        assert not self._unreachable_statements(text), f"unreachable statements in:\n{text}"

    def test_soap_puthex_residual_keeps_both_returns_reachable(self):
        """
        The repair this guards: without it the region loses both returns (and leaves a dangling goto behind);
        with it they are laid out with the labels their gotos name.
        """
        bin_path = os.path.join(test_location, "armel", "libsoap.so")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True)
        dec = proj.analyses.Decompiler(0x4114FC, cfg=cfg.model, options=[("structurer_cls", "phoenix")])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        assert not self._dangling_gotos(text), f"goto without a label in:\n{text}"
        assert not self._unreachable_statements(text), f"unreachable statements in:\n{text}"


if __name__ == "__main__":
    unittest.main()
