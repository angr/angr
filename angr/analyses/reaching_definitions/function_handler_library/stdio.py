from __future__ import annotations
import re
import random
import logging
from collections.abc import Iterable

import archinfo
import claripy

from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.key_definitions.live_definitions import DerefSize
from angr.sim_type import SimType, SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypePointer
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

# pylint: disable=no-self-use,missing-class-docstring,unused-argument

_l = logging.getLogger(__name__)


class StdoutAtom(Atom):
    def __init__(self, sink: str, size: int | None):
        self.nonce = random.randint(0, 999999999999)
        self.sink = sink
        super().__init__(size if size is not None else 1)

    def _identity(self):
        return (self.nonce,)

    def __repr__(self):
        return f"<StdoutAtom {self.sink}>"


class StdinAtom(Atom):
    def __init__(self, source: str, size: int | None):
        self.nonce = random.randint(0, 999999999999)
        self.source = source
        super().__init__(size if size is not None else 1)

    def _identity(self):
        return (self.nonce,)

    def __repr__(self):
        return f"<StdinAtom {self.source}>"


def parse_format_string(format_string: str) -> tuple[list[str | int], list[SimType], list[str]]:
    result_pieces: list[str | int] = []
    result_types: list[SimType] = []
    result_specs: list[str] = []

    last_piece = 0
    idx = 0
    for argspec in re.finditer(r"\%([0 #+-]?[0-9*]*\.?\d*([hl]{0,2}|[jztL])?[diuoxXeEfgGaAcpsSn%])", format_string):
        start, end = argspec.span()
        if format_string[end - 1] == "%":
            continue
        if start != last_piece:
            result_pieces.append(format_string[last_piece:start])
        result_pieces.append(idx)
        idx += 1
        fmt = format_string[start:end]
        if fmt == "%s":
            arg = SimTypePointer(SimTypeChar())
        elif fmt == "%d":
            arg = SimTypeInt(signed=True)
        elif fmt == "%u":
            arg = SimTypeInt(signed=False)
        elif fmt == "%c":
            arg = SimTypeChar(signed=True)
        else:
            arg = SimTypeBottom()
        result_types.append(arg)
        result_specs.append(fmt)
        last_piece = end
    if last_piece != len(format_string):
        result_pieces.append(format_string[last_piece:])

    return result_pieces, result_types, result_specs


class LibcStdioHandlers(FunctionHandler):
    @FunctionCallDataUnwrapped.decorate
    def handle_impl_printf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 0)
        dst_atoms = StdoutAtom("printf", len(result) if result is not None else None)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_dprintf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 1)
        dst_atoms = StdoutAtom("dprintf", len(result) if result is not None else None)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_fprintf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 1)
        dst_atoms = StdoutAtom("fprintf", len(result) if result is not None else None)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_sprintf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 1)
        dst_atoms = state.deref(data.args_atoms[0], size=len(result) // 8 if result is not None else 1)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_snprintf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 2)
        size = state.get_concrete_value(data.args_atoms[1]) or 2
        if result is not None:
            size = min(size, len(result) // 8)
        dst_atoms = state.deref(data.args_atoms[0], size=size)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl___sprintf_chk(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 3)
        dst_atoms = state.deref(data.args_atoms[0], size=len(result) // 8 if result is not None else 1)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl___snprintf_chk(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        result, source_atoms = handle_printf(state, data, 4)
        size = state.get_concrete_value(data.args_atoms[1]) or 2
        dst_atoms = state.deref(data.args_atoms[0], size=size)
        data.depends(dst_atoms, source_atoms, value=result)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_scanf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        handle_scanf(state, data, 0, {StdinAtom("scanf", None)})

    handle_impl___isoc99_scanf = handle_impl_scanf

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_sscanf(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        handle_scanf(state, data, 1, state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE))

    handle_impl___isoc99_sscanf = handle_impl_sscanf

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_fgets(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[1]) or 2
        dst_atom = state.deref(data.args_atoms[0], size)
        input_value = claripy.BVS("weh", (size - 1) * 8).concat(claripy.BVV(0, 8))
        data.depends(dst_atom, StdinAtom("fgets", size), value=input_value)
        data.depends(data.ret_atoms, data.args_atoms[0])

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_fgetc(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        data.depends(data.ret_atoms, StdinAtom(data.function.name, 1))

    handle_impl_getchar = handle_impl_getc = handle_impl_fgetc

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_fread(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[1]) or 1
        nmemb = state.get_concrete_value(data.args_atoms[1]) or 2
        dst_atom = state.deref(data.args_atoms[0], size * nmemb)
        data.depends(dst_atom, StdinAtom("fread", size * nmemb))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_fwrite(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[1]) or 1
        nmemb = state.get_concrete_value(data.args_atoms[1]) or 2
        src_atom = state.deref(data.args_atoms[0], size * nmemb)
        data.depends(StdoutAtom("fwrite", size * nmemb), src_atom, value=state.get_values(src_atom))


def handle_printf(
    state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped, fmt_idx: int
) -> tuple[MultiValues | None, Iterable[Atom]]:
    format_str = state.get_concrete_value(
        state.deref(data.args_atoms[fmt_idx], DerefSize.NULL_TERMINATE), cast_to=bytes
    )
    if format_str is None:
        _l.info("Hmmm.... non-constant format string")
        return None, set()

    format_str = format_str.strip(b"\0").decode()
    arg_pieces, arg_types, formats = parse_format_string(format_str)
    data.reset_prototype(SimTypeFunction(data.prototype.args + tuple(arg_types), data.prototype.returnty), state)

    result = MultiValues(claripy.BVV(b""))
    source_atoms: set[Atom] = set()
    for piece in arg_pieces:
        if isinstance(piece, str):
            if result is not None:
                result = result.concat(piece.encode())
            continue
        atom = data.args_atoms[fmt_idx + 1 + piece]
        fmt = formats[piece]

        if fmt == "%s":
            buf_atoms = state.deref(atom, DerefSize.NULL_TERMINATE)
            buf_data = state.get_values(buf_atoms)
            if buf_data is not None:
                buf_data = buf_data.extract(0, len(buf_data) // 8 - 1, archinfo.Endness.BE)
        elif fmt == "%u":
            buf_atoms = atom
            buf_data = state.get_concrete_value(buf_atoms)
            if buf_data is not None:
                buf_data = str(buf_data).encode()
        elif fmt == "%d":
            buf_atoms = atom
            buf_data = state.get_concrete_value(buf_atoms)
            if buf_data is not None:
                if buf_data >= 2**31:
                    buf_data -= 2**32
                buf_data = str(buf_data).encode()
        elif fmt == "%c":
            buf_atoms = atom
            buf_data = state.get_concrete_value(atom)
            if buf_data is not None:
                buf_data = chr(buf_data).encode()
        else:
            _l.warning("Unimplemented printf format string %s", fmt)
            buf_atoms = set()
            buf_data = None
        if result is not None and buf_data is not None:
            result = result.concat(buf_data)
        source_atoms.update(buf_atoms)
    if result is not None:
        result = result.concat(b"\0")

    return result, source_atoms


def handle_scanf(
    state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped, fmt_idx: int, source_atoms: Iterable[Atom]
):
    format_str = state.get_concrete_value(
        state.deref(data.args_atoms[fmt_idx], DerefSize.NULL_TERMINATE), cast_to=bytes
    )
    if format_str is None:
        _l.info("Hmmm.... non-constant format string")
        return
    format_str = format_str.strip(b"\0").decode()
    arg_pieces, arg_types, formats = parse_format_string(format_str)
    data.reset_prototype(SimTypeFunction(data.prototype.args + tuple(arg_types), data.prototype.returnty), state)

    for piece in arg_pieces:
        if isinstance(piece, str):
            continue
        atom = data.args_atoms[fmt_idx + 1 + piece]
        fmt = formats[piece]
        buf_data = None

        if fmt == "%s":
            buf_atom = state.deref(atom, 1)
            buf_data = b"\0"
        elif fmt == "%u" or fmt == "%d":
            buf_atom = state.deref(atom, 4, state.arch.memory_endness)
        elif fmt == "%c":
            buf_atom = state.deref(atom, 1, state.arch.memory_endness)
        else:
            _l.warning("Unimplemented scanf format string %s", fmt)
            continue
        data.depends(buf_atom, source_atoms, value=buf_data)
