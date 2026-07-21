from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from angr.protos import decompilation_cache_pb2
from angr.serializable import Serializable
from angr.utils.ail_serialization import (
    pack_arg_vvars,
    pack_ite_exprs,
    pack_static_buffers,
    pack_static_vvars,
    parse_arg_vvars,
    parse_ite_exprs,
    parse_static_buffers,
    parse_static_vvars,
)

from .clinic import Clinic

if TYPE_CHECKING:
    from angr import ailment
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
    from angr.analyses.typehoon.typevars import TypeConstraint, TypeVariable
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.cfg import CFGModel

    from .notes import DecompilationNote
    from .structured_codegen import BaseStructuredCodeGenerator
    from .variable_map import VariableMap


# ---------------------------------------------------------------------------------------------------------------------
# Serialization helpers.
#
# Conventions:
# - Heavy sub-objects (``clinic``, ``codegen``) are embedded as already-serialized bytes (each manages its own format).
# - AIL-typed top-level slots (``arg_vvars``, ``ite_exprs``) use the typed messages from ``ail_types.proto``.
# - ``cfg`` and ``variable_kb`` are intentionally not serialized — they come from the parent Project.
# - The 4 typehoon-typed slots are skipped entirely (typehoon is out of scope for now).
# ---------------------------------------------------------------------------------------------------------------------


def _simvar_to_bytes(v) -> bytes:
    return type(v).__name__.encode("ascii") + b"\0" + v.serialize()


def _simvar_from_bytes(b: bytes):
    import angr.sim_variable as sv_mod  # pylint:disable=import-outside-toplevel

    sep = b.index(b"\0")
    return getattr(sv_mod, b[:sep].decode("ascii")).parse(b[sep + 1 :])


def _serialize_binop_operators(binop_operators, out_msg, set_flag=None) -> None:
    if binop_operators is None:
        return
    if set_flag is not None:
        setattr(set_flag[0], set_flag[1], True)
    for op_desc, value in binop_operators.items():
        entry = out_msg.add()
        entry.key_json = op_desc.to_json()
        entry.value = value


def _parse_binop_operators(entries):
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import (  # pylint:disable=import-outside-toplevel
        OpDescriptor,
    )

    return {OpDescriptor.from_json(e.key_json): e.value for e in entries}


def _serialize_parameters(params: dict, out_msg) -> None:
    """Translate the 14-key parameters dict into a DecompilationParameters cmessage."""
    from angr.analyses.decompiler.optimization_pass_registry import (  # pylint:disable=import-outside-toplevel
        pass_to_name,
    )

    if "flavor" in params and params["flavor"] is not None:
        out_msg.flavor = params["flavor"]
    if "sp_tracker_track_memory" in params:
        out_msg.sp_tracker_track_memory = bool(params["sp_tracker_track_memory"])
    if "vars_must_struct" in params and params["vars_must_struct"] is not None:
        out_msg._vars_must_struct_set = True
        out_msg.vars_must_struct.extend(sorted(params["vars_must_struct"]))
    if "desired_variables" in params and params["desired_variables"] is not None:
        out_msg.desired_variables.extend(sorted(params["desired_variables"]))
    if "inline_functions" in params and params["inline_functions"] is not None:
        out_msg.inline_functions.extend(sorted(params["inline_functions"]))
    if params.get("options"):
        for option, value in params["options"]:
            entry = out_msg.options.add()
            entry.param = option.param
            try:
                entry.value_json = json.dumps(value)
            except (TypeError, ValueError):
                entry.value_json = json.dumps(None)
    if "optimization_passes" in params and params["optimization_passes"] is not None:
        out_msg._optimization_passes_set = True
        for cls in params["optimization_passes"]:
            out_msg.optimization_passes.append(pass_to_name(cls))
    if "peephole_optimizations" in params and params["peephole_optimizations"] is not None:
        out_msg._peephole_optimizations_set = True
        for cls in params["peephole_optimizations"]:
            out_msg.peephole_optimizations.append(pass_to_name(cls))
    if "expr_comments" in params and params["expr_comments"] is not None:
        out_msg._expr_comments_set = True
        for k, v in params["expr_comments"].items():
            out_msg.expr_comments[k] = v
    if "stmt_comments" in params and params["stmt_comments"] is not None:
        out_msg._stmt_comments_set = True
        for k, v in params["stmt_comments"].items():
            out_msg.stmt_comments[k] = v
    if "binop_operators" in params and params["binop_operators"] is not None:
        out_msg._binop_operators_set = True
        _serialize_binop_operators(params["binop_operators"], out_msg.binop_operators)
    if "ite_exprs" in params and params["ite_exprs"] is not None:
        out_msg.ite_exprs.CopyFrom(pack_ite_exprs(params["ite_exprs"]))
    if "static_vvars" in params and params["static_vvars"] is not None:
        out_msg.static_vvars.CopyFrom(pack_static_vvars(params["static_vvars"]))
    if "static_buffers" in params and params["static_buffers"] is not None:
        out_msg.static_buffers.CopyFrom(pack_static_buffers(params["static_buffers"]))


def _parse_parameters(msg) -> dict:
    """Always populate every one of the 14 keys in the returned dict, with None for fields that weren't set in the
    cmsg. This matches what the decompiler's _can_use_decompilation_cache expects when iterating over its own
    _cache_parameters and looking up each key in the deserialized cache."""
    from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION  # pylint:disable=import-outside-toplevel
    from angr.analyses.decompiler.optimization_pass_registry import (  # pylint:disable=import-outside-toplevel
        name_to_pass,
    )

    return {
        "flavor": msg.flavor if msg.HasField("flavor") else None,
        "sp_tracker_track_memory": msg.sp_tracker_track_memory if msg.HasField("sp_tracker_track_memory") else None,
        "vars_must_struct": set(msg.vars_must_struct) if msg._vars_must_struct_set else None,
        "desired_variables": frozenset(msg.desired_variables),
        "inline_functions": frozenset(msg.inline_functions),
        "options": {
            (PARAM_TO_OPTION[e.param], json.loads(e.value_json) if e.value_json else None)
            for e in msg.options
            if e.param in PARAM_TO_OPTION
        },
        "optimization_passes": (
            [name_to_pass(n) for n in msg.optimization_passes] if msg._optimization_passes_set else None
        ),
        "peephole_optimizations": (
            [name_to_pass(n) for n in msg.peephole_optimizations] if msg._peephole_optimizations_set else None
        ),
        "expr_comments": dict(msg.expr_comments) if msg._expr_comments_set else None,
        "stmt_comments": dict(msg.stmt_comments) if msg._stmt_comments_set else None,
        "binop_operators": _parse_binop_operators(msg.binop_operators) if msg._binop_operators_set else None,
        "ite_exprs": parse_ite_exprs(msg.ite_exprs) if msg.HasField("ite_exprs") else None,
        "static_vvars": parse_static_vvars(msg.static_vvars) if msg.HasField("static_vvars") else None,
        "static_buffers": parse_static_buffers(msg.static_buffers) if msg.HasField("static_buffers") else None,
    }


class DecompilationCache(Serializable):
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    # ``cfg`` and ``variable_kb`` are not part of the decompilation result: they are inputs supplied by the parent
    # Project at decompile time and are used only for in-memory cache-validity checks. They are intentionally not
    # serialized; on deserialization they come back as None and must be re-attached by the caller.
    __slots__ = (
        "addr",
        "arg_vvars",
        "binop_operators",
        "cfg",
        "clinic",
        "codegen",
        "errors",
        "func_typevar",
        "function_summary",
        "ite_exprs",
        "max_tv_id",
        "notes",
        "parameters",
        "stack_offset_typevars",
        "stackvar_max_sizes",
        "timestamp",
        "type_constraints",
        "var_to_typevar",
        "variable_kb",
        "variable_map",
        "version",
    )

    def __init__(self, addr):
        import angr  # pylint:disable=import-outside-toplevel,cyclic-import

        self.parameters: dict[str, Any] = {}
        # provenance stamps; the cache is created when decompilation happens
        self.version: str = angr.__version__
        self.timestamp: int = int(time.time())
        self.addr = addr
        self.cfg: CFGModel | None = None
        self.variable_kb: KnowledgeBase | None = None
        self.type_constraints: dict[TypeVariable, set[TypeConstraint]] | None = None
        self.arg_vvars: dict | None = None
        self.func_typevar: TypeVariable | None = None
        self.var_to_typevar: dict | None = None
        self.stackvar_max_sizes: dict | None = None
        self.stack_offset_typevars: dict | None = None
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.clinic: Clinic | None = None
        self.variable_map: VariableMap | None = None
        self.ite_exprs: set[tuple[int, ailment.Expression]] | None = None
        self.binop_operators: dict[OpDescriptor, str] | None = None
        self.errors: list[str] = []
        self.function_summary: str | None = None
        self.notes: dict[str, DecompilationNote] = {}
        self.max_tv_id: int = 0

    @property
    def local_types(self):
        if self.clinic is None or self.clinic.variable_kb is None:
            return None
        return self.clinic.variable_kb.variables[self.addr].types

    # -----------------------------------------------------------------------------------------------------------------
    # Protobuf serialization. Heavy sub-objects (clinic, codegen) are embedded as already-serialized bytes from their
    # own Serializable interfaces; AIL-typed top-level fields (arg_vvars, ite_exprs) use the typed messages from
    # ail_types.proto.
    #
    # The 4 typehoon-typed slots (type_constraints, func_typevar, var_to_typevar, stack_offset_typevars) and the
    # ``cfg`` / ``variable_kb`` runtime inputs are intentionally NOT serialized and come back as None.
    # -----------------------------------------------------------------------------------------------------------------

    @classmethod
    def _get_cmsg(cls):
        return decompilation_cache_pb2.DecompilationCache()

    def serialize_to_cmessage(self):
        msg = decompilation_cache_pb2.DecompilationCache(addr=self.addr)

        if self.clinic is not None:
            msg.clinic = self.clinic.serialize()
        if self.codegen is not None:
            msg.codegen = self.codegen.serialize()

        msg.errors.extend(self.errors)
        if self.function_summary is not None:
            msg.function_summary = self.function_summary
        if self.arg_vvars is not None:
            msg.arg_vvars.CopyFrom(pack_arg_vvars(self.arg_vvars))
        if self.ite_exprs is not None:
            msg.ite_exprs.CopyFrom(pack_ite_exprs(self.ite_exprs))
        if self.binop_operators is not None:
            msg._binop_operators_set = True
            _serialize_binop_operators(self.binop_operators, msg.binop_operators)
        if self.stackvar_max_sizes is not None:
            msg._stackvar_max_sizes_set = True
            for simvar, size in self.stackvar_max_sizes.items():
                entry = msg.stackvar_max_sizes.add()
                entry.simvar = _simvar_to_bytes(simvar)
                entry.max_size = size

        msg.version = self.version
        msg.timestamp = self.timestamp

        if self.parameters:
            msg.parameters_set = True
            _serialize_parameters(self.parameters, msg.parameters)

        for k, note in self.notes.items():
            msg.notes_json[k] = note.to_json()

        return msg

    @classmethod
    def parse_from_cmessage(
        cls,
        cmsg,
        *,
        project=None,
        kb=None,
        function=None,
        variable_kb=None,
        cfg=None,
        **_,
    ):
        """Parse a DecompilationCache from a cmessage. Runtime back-references (project, kb, function, variable_kb,
        cfg) are passed through to the embedded Clinic / codegen parsers so the parsed cache is functional for
        cache-hit validity checks."""
        from .notes import DecompilationNote  # pylint:disable=import-outside-toplevel
        from .structured_codegen.c import CStructuredCodeGenerator  # pylint:disable=import-outside-toplevel

        cache = cls(cmsg.addr)
        # cfg and variable_kb are not serialized; reattach from kwargs so cache-validity checks still work.
        cache.cfg = cfg
        cache.variable_kb = variable_kb

        if cmsg.HasField("clinic"):
            cache.clinic = Clinic.parse(
                cmsg.clinic, project=project, kb=kb, function=function, variable_kb=variable_kb, cfg=cfg
            )
        if cmsg.HasField("codegen"):
            cache.codegen = CStructuredCodeGenerator.parse(
                cmsg.codegen, project=project, kb=kb, variable_kb=variable_kb, func=function
            )

        cache.errors = list(cmsg.errors)
        if cmsg.HasField("function_summary"):
            cache.function_summary = cmsg.function_summary
        cache.arg_vvars = parse_arg_vvars(cmsg.arg_vvars) if cmsg.HasField("arg_vvars") else None
        cache.ite_exprs = parse_ite_exprs(cmsg.ite_exprs) if cmsg.HasField("ite_exprs") else None
        cache.binop_operators = _parse_binop_operators(cmsg.binop_operators) if cmsg._binop_operators_set else None
        if cmsg._stackvar_max_sizes_set:
            cache.stackvar_max_sizes = {_simvar_from_bytes(e.simvar): e.max_size for e in cmsg.stackvar_max_sizes}
        else:
            cache.stackvar_max_sizes = None

        # legacy blobs carry the proto3 defaults ""/0, meaning "unknown"; do not re-stamp them with current values
        cache.version = cmsg.version
        cache.timestamp = cmsg.timestamp
        if cache.codegen is not None:
            # mirror the stamps onto the codegen (a fresh decompile does the same in Decompiler._decompile)
            cache.codegen.version = cache.version
            cache.codegen.timestamp = cache.timestamp

        if cmsg.parameters_set:
            cache.parameters = _parse_parameters(cmsg.parameters)

        cache.notes = {k: DecompilationNote.from_json(v) for k, v in cmsg.notes_json.items()}

        return cache
