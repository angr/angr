from __future__ import annotations
import logging

from angr.ailment import Statement, Block, Assignment, BinaryOp
from angr.ailment.expression import Const, VirtualVariable, Load
from angr.ailment.block_walker import AILBlockViewer, AILBlockRewriter
from angr.ailment.statement import Call
from angr.sim_type import SimTypeWideChar, SimTypeChar, SimTypePointer
from angr.utils.graph import GraphUtils
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(__name__)


#
# Data types
#


class FixedBuffer:
    def __init__(self, ident: str | None, size: int, content: bytes):
        self.ident = ident or "<unnamed>"
        self.size = size
        self.content = content

    def __repr__(self):
        return f"<FixedBuffer {self.ident} size={self.size}>"


class FixedBufferPtr:
    def __init__(self, buffer_ident: str, offset: int = 0):
        self.buffer_ident = buffer_ident
        self.offset = offset

    def __repr__(self):
        return f"<FixedBufferPtr {self.buffer_ident} + {self.offset}>"


class Offset:
    def __init__(self, value: int, bits: int):
        self.value = value
        self.bits = bits

    def __repr__(self):
        return f"<Offset {self.value} ({self.bits} bits)>"


#
# Visitors
#


class VVarRewritingVisitor(AILBlockRewriter):
    """
    The visitor that rewrites vvars and their reads.
    """

    def __init__(self, static_buffers: dict[str, FixedBuffer], static_vvars: dict[int, FixedBufferPtr | Const], kb):
        super().__init__(update_block=False)
        self._static_buffers = static_buffers
        self._static_vvars = static_vvars
        self.kb = kb

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if expr.varid in self._static_vvars:
            v = self._static_vvars[expr.varid]
            if isinstance(v, Const):
                return v
        return None

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        if isinstance(expr.addr, VirtualVariable) and expr.addr.varid in self._static_vvars:
            v = self._static_vvars[expr.addr.varid]
            if isinstance(v, FixedBufferPtr):
                buffer = self._static_buffers.get(v.buffer_ident, None)
                if buffer is None:
                    _l.warning("Cannot find static buffer %s", v.buffer_ident)
                    return None
                if v.offset < 0 or v.offset + expr.size > buffer.size:
                    _l.warning(
                        "Static buffer %s access out of bounds: offset=%d, size=%d, buffer_size=%d",
                        v.buffer_ident,
                        v.offset,
                        expr.size,
                        buffer.size,
                    )
                    return None
                data = buffer.content[v.offset : v.offset + expr.size]
                value = int.from_bytes(data, byteorder="little" if expr.endness == "Iend_LE" else "big")
                return Const(None, None, value, expr.bits, **expr.tags)

        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        if expr.target in {"strlen", "wcslen"} and expr.args:
            arg = expr.args[0]
            if isinstance(arg, VirtualVariable) and arg.varid in self._static_vvars:
                v = self._static_vvars[arg.varid]
                if isinstance(v, FixedBufferPtr):
                    buffer = self._static_buffers.get(v.buffer_ident, None)
                    if buffer is None:
                        _l.warning("Cannot find static buffer %s", v.buffer_ident)
                        return None
                    # compute the length of the string in the buffer
                    data = buffer.content[v.offset :]
                    str_len = 0
                    word_size = 2 if expr.target == "wcslen" else 1
                    while (
                        str_len < len(data)
                        and data[str_len * word_size : str_len * word_size + word_size] != b"\x00" * word_size
                    ):
                        str_len += 1
                    return Const(None, None, str_len, expr.bits, **expr.tags)

        elif expr.args and expr.prototype is not None:
            new_args: list | None = None
            for arg_idx, (arg_type, arg) in enumerate(zip(expr.prototype.args, expr.args)):
                if (  # noqa:SIM102
                    isinstance(arg, VirtualVariable)
                    and arg.varid in self._static_vvars
                    and isinstance(self._static_vvars[arg.varid], FixedBufferPtr)
                ):
                    if isinstance(arg_type, SimTypePointer):
                        if isinstance(arg_type.pts_to, SimTypeChar):
                            # char*
                            data = self._static_buffers[self._static_vvars[arg.varid].buffer_ident].content
                            offset = self._static_vvars[arg.varid].offset
                            str_bytes = bytearray()
                            idx = offset
                            while idx < len(data):
                                byte = data[idx : idx + 1]
                                if byte == b"\x00":
                                    break
                                str_bytes += byte
                                idx += 1
                            str_id = self.kb.custom_strings.allocate(bytes(str_bytes))
                            str_id_arg = Const(
                                None,
                                None,
                                str_id,
                                arg.bits,
                                custom_string=True,
                                **arg.tags,
                            )
                            if new_args is None:
                                new_args = expr.args[:arg_idx]
                            new_args.append(str_id_arg)
                            continue

                        if isinstance(arg_type.pts_to, SimTypeWideChar):
                            # wchar*
                            data = self._static_buffers[self._static_vvars[arg.varid].buffer_ident].content
                            offset = self._static_vvars[arg.varid].offset
                            str_bytes = bytearray()
                            idx = offset
                            while idx + 2 <= len(data):
                                wchar_bytes = data[idx : idx + 2]
                                if wchar_bytes == b"\x00\x00":
                                    break
                                str_bytes += wchar_bytes
                                idx += 2
                            str_id = self.kb.custom_strings.allocate(bytes(str_bytes))
                            str_id_arg = Const(
                                None,
                                None,
                                str_id,
                                arg.bits,
                                custom_string=True,
                                **arg.tags,
                            )
                            if new_args is None:
                                new_args = expr.args[:arg_idx]
                            new_args.append(str_id_arg)
                            continue

                if new_args is not None:
                    new_args.append(arg)

            if new_args is not None:
                return Call(
                    expr.idx,
                    expr.target,
                    calling_convention=expr.calling_convention,
                    prototype=expr.prototype,
                    args=new_args,
                    ret_expr=expr.ret_expr,
                    fp_ret_expr=expr.fp_ret_expr,
                    bits=expr.bits,
                    **expr.tags,
                )

        return None


class VVarAliasVisitor(AILBlockViewer):
    """
    The visitor that discovers const assignments and aliases of existing static vvars.
    """

    def __init__(self, static_buffers: dict[str, FixedBuffer], static_vvars: dict[int, FixedBufferPtr | Const], kb):
        super().__init__()
        self._static_buffers = static_buffers
        self._static_vvars = static_vvars
        self.kb = kb

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        dst = stmt.dst
        if (
            isinstance(dst, VirtualVariable)
            and dst.varid not in self._static_vvars
            and src is not None
            and isinstance(src, FixedBufferPtr)
        ):
            self._static_vvars[dst.varid] = src

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        return self._static_vvars.get(expr.varid, None)

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement, block: Block | None):
        return Offset(expr.value, expr.bits)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        if (
            stmt.target == "memcpy"
            and isinstance(stmt.args[0], VirtualVariable)
            and isinstance(stmt.args[1], Const)
            and isinstance(stmt.args[2], Const)
        ):
            # got a new memcpy call that we can handle
            dst, src, size = stmt.args
            if dst.varid not in self._static_vvars:
                if src.tags.get("custom_string", False):
                    ident = f"static_buf_{stmt.tags['ins_addr']}"
                    buf = self.kb.custom_strings[src.value_int]
                    fixed_buffer = FixedBuffer(ident, size.value_int, buf)
                else:
                    # TODO: Support other cases
                    return super()._handle_Call(stmt_idx, stmt, block)
                if ident not in self._static_buffers:
                    self._static_buffers[ident] = fixed_buffer
                self._static_vvars[dst.varid] = FixedBufferPtr(ident, 0)

        return super()._handle_Call(stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        op0 = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        op1 = self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        if op0 is None or op1 is None:
            return None
        if expr.op == "Add":
            if isinstance(op0, FixedBufferPtr) and isinstance(op1, Offset):
                return FixedBufferPtr(op0.buffer_ident, op0.offset + op1.value)
            if isinstance(op1, FixedBufferPtr) and isinstance(op0, Offset):
                return FixedBufferPtr(op1.buffer_ident, op1.offset + op0.value)
        elif expr.op == "Sub":
            if isinstance(op0, FixedBufferPtr) and isinstance(op1, Offset):
                return FixedBufferPtr(op0.buffer_ident, op0.offset - op1.value)
        elif expr.op == "Mul":
            if isinstance(op0, Offset) and isinstance(op1, Offset):
                return Offset(op0.value * op1.value, expr.bits)
        return None


#
# The main class
#


class StaticVVarRewriter(OptimizationPass):
    """
    Rewrite user-specified vvars as static values or fix-sized buffers. Also rewrites reads from pointers derived off
    of such vvars.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Static virtual variable rewriter"
    DESCRIPTION = __doc__.strip()

    def __init__(
        self,
        func,
        static_buffers: dict[str, FixedBuffer] | None = None,
        static_vvars: dict[int, FixedBufferPtr | Const] | None = None,
        **kwargs,
    ):
        super().__init__(func, **kwargs)
        self._static_buffers = static_buffers
        self._static_vvars = static_vvars
        self.analyze()

    def _check(self):
        # discover aliases
        alias_visitor = VVarAliasVisitor(self._static_buffers, self._static_vvars, self.kb)
        head = {(node.addr, node.idx): node for node in self._graph}[self.entry_node_addr]
        for block in reversed(list(GraphUtils.dfs_postorder_nodes_deterministic(self._graph, head))):
            alias_visitor.walk(block)
        if not self._static_buffers or not self._static_vvars:
            return False, None
        return True, None

    def _analyze(self, cache=None):
        # rewrite vvars
        g = self._graph

        rewritten = False
        while True:
            rewriter = VVarRewritingVisitor(self._static_buffers, self._static_vvars, self.kb)
            for block in list(g):
                new_block = rewriter.walk(block)
                if new_block is not None:
                    rewritten = True
                    self._update_block(block, new_block)

            if not rewritten:
                break

            g = self.out_graph
            # discover more aliases
            old_static_buffers = dict(self._static_buffers)
            old_static_vvars = dict(self._static_vvars)
            alias_visitor = VVarAliasVisitor(self._static_buffers, self._static_vvars, self.kb)
            head = {(node.addr, node.idx): node for node in g}[self.entry_node_addr]
            for block in reversed(list(GraphUtils.dfs_postorder_nodes_deterministic(g, head))):
                alias_visitor.walk(block)

            if old_static_buffers == self._static_buffers and old_static_vvars == self._static_vvars:
                # no new aliases found
                break
