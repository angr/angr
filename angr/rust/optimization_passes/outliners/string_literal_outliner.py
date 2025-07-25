from collections import OrderedDict

from angr.ailment import AILBlockWalker, Block
from angr.ailment.expression import Struct, Const, StringLiteral
from angr.ailment.statement import Statement
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.utils import extract_str


class StringLiteralOutliner(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline struct fields to string literals"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        def callback(expr: Struct):
            new_fields = OrderedDict()
            new_field_offsets = {}
            field_names = sorted(list(expr.field_names.items()), key=lambda ele: ele[0])
            changed = False
            while len(field_names) >= 2:
                offset, field_name = field_names.pop(0)
                field = expr.fields.get(offset, None)
                next_offset, next_field_name = field_names.pop(0)
                next_field = expr.fields.get(next_offset, None)
                if (
                    field
                    and next_field
                    and next_offset - offset == self.project.arch.bytes
                    and field.size == self.project.arch.bytes
                    and next_field.size == self.project.arch.bytes
                    and isinstance(field, Const)
                    and isinstance(next_field, Const)
                ):
                    string_literal = extract_str(self.project, field.value, next_field.value)
                    if string_literal is not None:
                        new_fields[offset] = StringLiteral(None, string_literal, self.project.arch.bits * 2)
                        new_field_offsets[field_name] = offset
                        changed = True
                        continue
                new_fields[offset] = field
                new_field_offsets[field_name] = offset
                field_names.insert(0, (next_offset, next_field_name))
            if len(field_names):
                offset, field_name = field_names.pop(0)
                field = expr.fields.get(offset, None)
                new_fields[offset] = field
                new_field_offsets[field_name] = offset
            return (
                Struct(expr.idx, expr.name, new_fields, new_field_offsets, expr.bits, **expr.tags) if changed else None
            )

        class StructWalker(AILBlockWalker):

            def _handle_Struct(self, expr_idx: int, expr: Struct, stmt_idx: int, stmt: Statement, block: Block | None):
                return callback(expr)

        walker = StructWalker()
        for block in self._graph.nodes:
            walker.walk(block)

        self.out_graph = self._graph
