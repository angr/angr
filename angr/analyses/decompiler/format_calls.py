from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple

import archinfo

from angr.ailment import AILBlockViewer
from angr.ailment.expression import (
    Call,
    Const,
    Convert,
    Expression,
    Extract,
    Phi,
    StackBaseOffset,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, Statement, Store

if TYPE_CHECKING:
    import networkx


class CallMemoryEffect(NamedTuple):
    """
    The memory a call touches through its arguments, when that is all it touches.

    ``reads`` are pointers the callee may read through. ``writes`` are write-only pointers with the number of bytes
    the callee is taken to write through them (0: possibly none). The callee keeps none of these pointers.
    """

    reads: tuple[Expression, ...]
    writes: tuple[tuple[Expression, int], ...]


# name -> (format argument index, stream/source arguments read, buffers written, scanf-like, wide)
_FORMAT_CALLS: dict[str, tuple[int, tuple[int, ...], tuple[int, ...], bool, bool]] = {
    "printf": (0, (), (), False, False),
    "wprintf": (0, (), (), False, True),
    "fprintf": (1, (0,), (), False, False),
    "fwprintf": (1, (0,), (), False, True),
    "sprintf": (1, (), (0,), False, False),
    "snprintf": (2, (), (0,), False, False),
    "_snprintf": (2, (), (0,), False, False),
    "scanf": (0, (), (), True, False),
    "wscanf": (0, (), (), True, True),
    "fscanf": (1, (0,), (), True, False),
    "fwscanf": (1, (0,), (), True, True),
    "sscanf": (1, (0,), (), True, False),
    "swscanf": (1, (0,), (), True, True),
}
for _name in ("scanf", "fscanf", "sscanf", "wscanf", "fwscanf", "swscanf"):
    _FORMAT_CALLS["__isoc99_" + _name] = _FORMAT_CALLS[_name]

_PRINTF_DIRECTIVE = re.compile(
    rb"%[-+ #0']*(?P<width>[0-9]*)(?:\.[0-9]*)?(?P<mod>hh|h|ll|l|L|j|z|t)?(?P<conv>[diouxXeEfFgGaAcspn])"
)
_SCANF_DIRECTIVE = re.compile(rb"%(?P<width>[0-9]*)(?P<mod>hh|h|ll|l|L|j|z|t)?(?P<conv>[diouxXeEfFgGaAcspn])")
# bytes every C runtime stores for a scanf integer conversion with this length modifier (old msvcrt reads hh as h)
_SCANF_INT_BYTES = {b"hh": 1, b"h": 2, b"": 4, b"l": 4, b"ll": 8}
_SCANF_FLOAT_BYTES = {b"": 4, b"l": 8}


class FormatCallModel:
    """
    Memory effects of printf- and scanf-family library calls whose format string is a constant.

    Such a callee reads caller memory only through its stream or source-string argument and the ``%s`` arguments of
    a printf, writes only through its destination buffer and its ``%n`` / scanf conversion arguments, and keeps none
    of those pointers. A scanf conversion argument is write-only; it counts as written only for conversions whose
    width is the same in every C runtime, and only on the assumption that the conversion assigns -- on an input or
    matching failure the object keeps its old value. Anything unrecognised (a writable or non-constant format, ``*``
    widths, scansets, length modifiers outside the table, an argument count that does not match the format) leaves
    the call unmodelled.
    """

    def __init__(self, project, kb=None):
        self._project = project
        self._kb = kb if kb is not None else project.kb
        self._formats: dict[tuple[int, int, bool], list[tuple[bytes, bytes, bytes]] | None] = {}

    def callee_name(self, call: Call) -> str | None:
        """The name of a library callee: a hooked function, a SimProcedure, or an import stub."""
        target = call.target
        if not (isinstance(target, Const) and isinstance(target.value, int)):
            return None
        addr = target.value_int
        func = self._kb.functions.get(addr, None)
        if self._project.is_hooked(addr):
            return func.name if func is not None else self._project.hooked_by(addr).display_name
        if func is not None and (func.is_simprocedure or func.is_plt):
            return func.name
        return None

    def effect(self, call: Call, written_globals: list[tuple[int, int]] = ()) -> CallMemoryEffect | None:
        """
        :param written_globals: (address, size) of every constant-address store of the function.
        """
        name = self.callee_name(call)
        spec = _FORMAT_CALLS.get(name) if name is not None else None
        if spec is None or call.args is None:
            return None
        fmt_idx, read_idxs, buffer_idxs, scanf_like, wide = spec
        args = list(call.args)
        if len(args) <= fmt_idx:
            return None
        fmt = args[fmt_idx]
        if not (isinstance(fmt, Const) and isinstance(fmt.value, int)):
            return None
        char_size = self._wchar_size() if wide else 1
        if char_size is None:
            return None
        directives = self._directives(fmt.value_int, char_size, scanf_like, written_globals)
        if directives is None or len(args) != fmt_idx + 1 + len(directives):
            return None

        reads = [args[i] for i in read_idxs]
        writes = [(args[i], 0) for i in buffer_idxs]
        for (width, mod, conv), arg in zip(directives, args[fmt_idx + 1 :]):
            if scanf_like:
                writes.append((arg, self._scanf_bytes(width, mod, conv, wide)))
            elif conv == b"n":
                writes.append((arg, 0))
            elif conv == b"s":
                reads.append(arg)
        return CallMemoryEffect(tuple(reads), tuple(writes))

    def _wchar_size(self) -> int | None:
        import cle  # pylint:disable=import-outside-toplevel

        main = self._project.loader.main_object
        if isinstance(main, cle.PE):
            return 2
        if isinstance(main, cle.ELF):
            return 4
        return None

    def _scanf_bytes(self, digits: bytes, mod: bytes, conv: bytes, wide: bool) -> int:
        """Bytes a scanf conversion stores when it assigns, if that is the same in every C runtime; else 0."""
        if conv in b"diouxX":
            return _SCANF_INT_BYTES.get(mod, 0)
        if conv in b"eEfFgGaA":
            return _SCANF_FLOAT_BYTES.get(mod, 0)
        if conv == b"c" and not wide and not mod:
            return int(digits) if digits else 1
        if conv == b"p" and not mod:
            return self._project.arch.bytes
        if conv == b"n" and not mod:
            return 4
        return 0

    def _directives(
        self, addr: int, char_size: int, scanf_like: bool, written_globals
    ) -> list[tuple[bytes, bytes, bytes]] | None:
        """(width, length modifier, conversion) of every directive of the format string that takes an argument."""
        key = addr, char_size, scanf_like
        if key in self._formats:
            return self._formats[key]
        self._formats[key] = None
        memory = self._project.loader.memory
        endness = "big" if self._project.arch.memory_endness == archinfo.Endness.BE else "little"
        chars = bytearray()
        try:
            for pos in range(addr, addr + 4096 * char_size, char_size):
                unit = int.from_bytes(memory.load(pos, char_size), endness)
                if unit == 0:
                    break
                if unit > 0x7F:
                    return None
                chars.append(unit)
            else:
                return None
        except KeyError:
            return None
        end = addr + (len(chars) + 1) * char_size
        if any(a < end and addr < a + n for a, n in written_globals):
            # the function may rewrite its format string
            return None

        directives = []
        pattern = _SCANF_DIRECTIVE if scanf_like else _PRINTF_DIRECTIVE
        text = bytes(chars)
        i = 0
        while i < len(text):
            if text[i] != ord("%"):
                i += 1
                continue
            if text[i + 1 : i + 2] == b"%":
                i += 2
                continue
            match = pattern.match(text, i)
            if match is None:
                # e.g. a "*" width, an assignment suppression, or a scanset
                return None
            directives.append((match.group("width") or b"", match.group("mod") or b"", match.group("conv")))
            i = match.end()

        from angr.procedures.stubs.format_parser import (  # pylint:disable=import-outside-toplevel
            FormatParser,
            FormatSpecifier,
            ScanfFormatParser,
        )

        # the decompiler attaches as many variadic arguments as angr's parser finds
        parser = (ScanfFormatParser if scanf_like else FormatParser)(project=self._project)
        components = parser.extract_components([bytes([c]) for c in text])
        if sum(1 for c in components if isinstance(c, FormatSpecifier)) != len(directives):
            return None
        self._formats[key] = directives
        return directives


class _Access(NamedTuple):
    varid: int
    kind: str  # "read" or "ref"
    offset: int
    size: int
    expr: Expression


class _StackVarAccesses(AILBlockViewer):
    """
    Every mention of a stack variable in a statement: a read of some of its bytes, or a reference to some of them.
    """

    def __init__(self):
        super().__init__()
        self.found: list[_Access] = []
        self.frame_pointers: list[int] = []

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr, StackBaseOffset):
            self.frame_pointers.append(expr.offset)
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    @staticmethod
    def _sub(expr: Expression) -> tuple[VirtualVariable, int, int] | None:
        """(variable, byte offset, size) for a variable or a constant little-endian extract of one."""
        if isinstance(expr, VirtualVariable) and expr.was_stack:
            return expr, 0, expr.size
        if (
            isinstance(expr, Extract)
            and isinstance(expr.base, VirtualVariable)
            and expr.base.was_stack
            and isinstance(expr.offset, Const)
            and expr.endness == archinfo.Endness.LE
            and expr.bits % 8 == 0
        ):
            return expr.base, expr.offset.value_int, expr.bits // 8
        return None

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if isinstance(stmt.dst, VirtualVariable):
            # a definition, not a mention
            self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
            return
        super()._handle_Assignment(stmt_idx, stmt, block)

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        for _, vvar in expr.src_and_vvars:
            if vvar is not None and vvar.was_stack:
                self.found.append(_Access(vvar.varid, "read", 0, vvar.size, vvar))

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            self.found.append(_Access(expr.varid, "read", 0, expr.size, expr))

    def _handle_Extract(self, expr_idx, expr, stmt_idx, stmt, block):
        sub = self._sub(expr)
        if sub is None:
            super()._handle_Extract(expr_idx, expr, stmt_idx, stmt, block)
            return
        self.found.append(_Access(sub[0].varid, "read", sub[1], sub[2], expr))

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        operand = expr.operand
        if (
            isinstance(operand, VirtualVariable)
            and operand.was_stack
            and expr.from_type == Convert.TYPE_INT
            and expr.to_type == Convert.TYPE_INT
            and expr.from_bits == operand.bits
            and expr.to_bits < expr.from_bits
            and expr.to_bits % 8 == 0
            and self._little_endian
        ):
            # a truncation reads the low bytes
            self.found.append(_Access(operand.varid, "read", 0, expr.to_bits // 8, expr))
            return
        super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference":
            sub = self._sub(expr.operand)
            if sub is not None:
                self.found.append(_Access(sub[0].varid, "ref", sub[1], sub[2], expr))
                return
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    _little_endian = True

    def collect(self, stmt: Statement, little_endian: bool) -> list[_Access]:
        self.found = []
        self._little_endian = little_endian
        self.walk_statement(stmt)
        return self.found


class _Calls(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.found: list[Call] = []

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.found.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


def _calls_in(stmt: Statement) -> list[Call]:
    collector = _Calls()
    collector.walk_statement(stmt)
    return collector.found


def find_defs_overwritten_by_calls(
    graph: networkx.DiGraph, model: FormatCallModel, arch
) -> dict[tuple[int, int | None], set[int]]:
    """
    Definitions of stack variables whose value nothing can read: the next mention of the variable is a modelled call
    that writes every byte that any other mention reads, and the variable is referenced nowhere else.

    The definition and the call are in one block with no mention of the variable between them, so every path from
    the definition to a read passes through the call. This relies on the assumption FormatCallModel states for scanf
    conversions: they assign.
    """
    if arch.memory_endness != archinfo.Endness.LE:
        # byte offsets below are little-endian
        return {}
    little_endian = True
    collector = _StackVarAccesses()
    ref_slots: list[tuple[int, int, int]] = []
    accesses: dict[tuple, list[_Access]] = {}
    by_var: dict[int, list[tuple[tuple, _Access]]] = {}
    defs: list[tuple[tuple, Assignment]] = []
    written_globals = []
    for block in graph:
        for idx, stmt in enumerate(block.statements):
            loc = (block.addr, block.idx, idx)
            found = collector.collect(stmt, little_endian)
            accesses[loc] = found
            for access in found:
                by_var.setdefault(access.varid, []).append((loc, access))
                if access.kind == "ref":
                    base = access.expr.operand
                    var = base if isinstance(base, VirtualVariable) else base.base
                    ref_slots.append((access.varid, var.stack_offset, var.size))
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                defs.append((loc, stmt))
            if isinstance(stmt, Store) and isinstance(stmt.addr, Const) and isinstance(stmt.addr.value, int):
                written_globals.append((stmt.addr.value_int, stmt.size))

    if collector.frame_pointers:
        # a raw frame address may reach any slot
        return {}
    blocks = {(b.addr, b.idx): b for b in graph}
    dead: dict[tuple[int, int | None], set[int]] = {}
    referenced = {vid for vid, _, _ in ref_slots}
    for (addr, bidx, idx), stmt in defs:
        var = stmt.dst
        if var.varid not in referenced or isinstance(stmt.src, Phi) or _calls_in(stmt):
            continue
        block = blocks[(addr, bidx)]
        call_idx = next(
            (j for j in range(idx + 1, len(block.statements)) if any(a.varid == var.varid for a in accesses[(addr, bidx, j)])),
            None,
        )
        if call_idx is None:
            continue
        start, end = var.stack_offset, var.stack_offset + var.size
        if any(vid != var.varid and off < end and start < off + size for vid, off, size in ref_slots):
            # another version of the slot has its address taken
            continue
        covered = _written_bytes(block.statements[call_idx], accesses[(addr, bidx, call_idx)], var, model, written_globals)
        if not covered:
            continue
        if all(
            loc == (addr, bidx, call_idx) or (a.kind == "read" and all(b in covered for b in range(a.offset, a.offset + a.size)))
            for loc, a in by_var.get(var.varid, ())
        ):
            dead.setdefault((addr, bidx), set()).add(idx)
    return dead


def _written_bytes(stmt: Statement, mentions: list[_Access], var: VirtualVariable, model, written_globals) -> set[int]:
    """
    The bytes of ``var`` the calls in ``stmt`` are known to write, provided every mention of ``var`` there is a
    write-only destination of a modelled call; else nothing.
    """
    calls = _calls_in(stmt)
    if len(calls) != 1:
        return set()
    effect = model.effect(calls[0], written_globals)
    if effect is None:
        return set()
    mine = [a for a in mentions if a.varid == var.varid]
    covered: set[int] = set()
    matched = 0
    for ptr, size in effect.writes:
        ref = next((a for a in mine if a.kind == "ref" and a.expr.likes(ptr)), None)
        if ref is None:
            continue
        matched += 1
        covered |= set(range(ref.offset, min(ref.offset + size, var.size)))
    if matched != len(mine) or any(a.kind != "ref" for a in mine):
        return set()
    return covered
