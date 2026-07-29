from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import CExpression, CIfElse, CLabel, CReturn, CStatements


class _Condition(CExpression):
    @property
    def type(self):
        return None

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield "condition", None


class _Codegen(DummyStructuredCodeGenerator):
    braces_on_own_lines: bool
    display_block_addrs: bool
    indent_delta: int


def _codegen():
    codegen = _Codegen(
        "c",
        expr_comments={},
        stmt_comments={},
        configuration={},
        const_formats={},
    )
    codegen.braces_on_own_lines = False
    codegen.display_block_addrs = False
    codegen.indent_delta = 4
    return codegen


def _render(node, indent=0):
    return "".join(text for text, _ in node.c_repr_chunks(indent=indent))


def test_trailing_label_has_null_statement():
    codegen = _codegen()
    statements = CStatements([CLabel("LABEL_400000", codegen=codegen)], codegen=codegen)

    assert _render(statements, indent=4) == "LABEL_400000:\n    ;\n"


def test_trailing_label_run_has_one_null_statement():
    codegen = _codegen()
    statements = CStatements(
        [
            CLabel("LABEL_400000", codegen=codegen),
            CLabel("LABEL_400010", codegen=codegen),
        ],
        codegen=codegen,
    )

    assert _render(statements, indent=4) == "LABEL_400000:\nLABEL_400010:\n    ;\n"


def test_trailing_label_does_not_capture_outer_statement():
    codegen = _codegen()
    conditional = CIfElse(
        [
            (
                _Condition(codegen=codegen),
                CStatements([CLabel("LABEL_400000", codegen=codegen)], codegen=codegen),
            )
        ],
        cstyle_ifs=True,
        codegen=codegen,
    )
    statements = CStatements([conditional, CReturn(None, codegen=codegen)], codegen=codegen)

    assert _render(statements) == "if (condition)\nLABEL_400000:\n    ;\nreturn;\n"
