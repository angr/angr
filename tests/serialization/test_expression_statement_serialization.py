from __future__ import annotations

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import CExpressionStatement, CFakeVariable
from angr.analyses.decompiler.structured_codegen.c_serialize import parse_subtree, serialize_subtree
from angr.sim_type import SimTypeInt


def _expression_statement(returning: bool | None):
    project = angr.load_shellcode(b"\xc3", arch="amd64")
    codegen = DummyStructuredCodeGenerator("pseudocode", expr_comments={}, stmt_comments={}, const_formats={})
    codegen.project = project
    expression = CFakeVariable("callee()", SimTypeInt(), codegen=codegen)
    return CExpressionStatement(expression, returning=returning, codegen=codegen), codegen


def _attach_codegen(statement, codegen):
    statement.codegen = codegen
    statement.expr.codegen = codegen


def test_unknown_returning_is_conservative_and_cacheable():
    statement, codegen = _expression_statement(None)
    assert statement.returning is True
    assert statement.c_repr() == "callee();\n"

    # Also cover nodes made before constructor normalization (including the Castle repro): serialization must not
    # assign None to protobuf's bool field, and rendering must not claim an unproved non-returning call.
    statement.returning = None
    assert statement.c_repr() == "callee();\n"
    back = parse_subtree(serialize_subtree(statement), project=codegen.project)
    assert isinstance(back, CExpressionStatement)
    assert back.returning is True
    _attach_codegen(back, codegen)
    assert back.c_repr() == "callee();\n"


def test_explicit_nonreturning_roundtrip():
    statement, codegen = _expression_statement(False)
    assert statement.returning is False
    assert statement.c_repr() == "callee(); /* do not return */\n"

    back = parse_subtree(serialize_subtree(statement), project=codegen.project)
    assert isinstance(back, CExpressionStatement)
    assert back.returning is False
    _attach_codegen(back, codegen)
    assert back.c_repr() == "callee(); /* do not return */\n"
