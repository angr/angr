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
# - ``cfg`` is intentionally not serialized — it comes from the parent Project. Decompilation variables live on
#   kb.dec_variables.
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
    """Translate the 15-key parameters dict into a DecompilationParameters cmessage."""
    from angr.analyses.decompiler.optimization_pass_registry import (  # pylint:disable=import-outside-toplevel
        pass_to_name,
    )

    if params.get("flavor") is not None:
        out_msg.flavor = params["flavor"]
    if "sp_tracker_track_memory" in params:
        out_msg.sp_tracker_track_memory = bool(params["sp_tracker_track_memory"])
    # Collection-typed parameters are never None (the Decompiler normalizes them to empty collections), so each is
    # written directly; an empty collection is left unset and parses back to empty.
    out_msg.vars_must_struct.extend(sorted(params.get("vars_must_struct") or ()))
    out_msg.desired_variables.extend(sorted(params.get("desired_variables") or ()))
    out_msg.inline_functions.extend(sorted(params.get("inline_functions") or ()))
    for option, value in params.get("options") or ():
        entry = out_msg.options.add()
        entry.param = option.param
        try:
            entry.value_json = json.dumps(value)
        except (TypeError, ValueError):
            entry.value_json = json.dumps(None)
    for cls in params.get("optimization_passes") or ():
        out_msg.optimization_passes.append(pass_to_name(cls))
    for cls in params.get("peephole_optimizations") or ():
        out_msg.peephole_optimizations.append(pass_to_name(cls))
    for k, v in (params.get("expr_comments") or {}).items():
        out_msg.expr_comments[k] = v
    for k, v in (params.get("stmt_comments") or {}).items():
        out_msg.stmt_comments[k] = v
    _serialize_binop_operators(params.get("binop_operators") or {}, out_msg.binop_operators)
    if params.get("ite_exprs"):
        out_msg.ite_exprs.CopyFrom(pack_ite_exprs(params["ite_exprs"]))
    if params.get("static_vvars"):
        out_msg.static_vvars.CopyFrom(pack_static_vvars(params["static_vvars"]))
    if params.get("static_buffers"):
        out_msg.static_buffers.CopyFrom(pack_static_buffers(params["static_buffers"]))
    out_msg.save_unoptimized_graph = bool(params.get("save_unoptimized_graph"))


def _parse_parameters(msg) -> dict:
    """Always populate every one of the 15 keys in the returned dict; scalar fields that were not set come back as
    None and collection fields come back empty. This matches the decompiler's normalized _cache_parameters, which
    _can_use_decompilation_cache compares key by key against the deserialized cache."""
    from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION  # pylint:disable=import-outside-toplevel
    from angr.analyses.decompiler.optimization_pass_registry import (  # pylint:disable=import-outside-toplevel
        name_to_pass,
    )

    # Collection-typed values come back as empty collections (never None) so they match the Decompiler's normalized
    # _cache_parameters during cache-validity comparison.
    return {
        "flavor": msg.flavor if msg.HasField("flavor") else None,
        "sp_tracker_track_memory": msg.sp_tracker_track_memory if msg.HasField("sp_tracker_track_memory") else None,
        "vars_must_struct": set(msg.vars_must_struct),
        "desired_variables": frozenset(msg.desired_variables),
        "inline_functions": frozenset(msg.inline_functions),
        "options": {
            (PARAM_TO_OPTION[e.param], json.loads(e.value_json) if e.value_json else None)
            for e in msg.options
            if e.param in PARAM_TO_OPTION
        },
        "optimization_passes": [name_to_pass(n) for n in msg.optimization_passes],
        "peephole_optimizations": [name_to_pass(n) for n in msg.peephole_optimizations],
        "expr_comments": dict(msg.expr_comments),
        "stmt_comments": dict(msg.stmt_comments),
        "binop_operators": _parse_binop_operators(msg.binop_operators),
        "ite_exprs": parse_ite_exprs(msg.ite_exprs) if msg.HasField("ite_exprs") else set(),
        "static_vvars": parse_static_vvars(msg.static_vvars) if msg.HasField("static_vvars") else {},
        "static_buffers": parse_static_buffers(msg.static_buffers) if msg.HasField("static_buffers") else {},
        "save_unoptimized_graph": msg.save_unoptimized_graph,
    }


class DecompilationCache(Serializable):
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    # ``cfg`` is a decompile-time input used only for cache-validity checks. It is not serialized; after
    # deserialization it is None until the caller re-attaches it.
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
        "variable_map",
        "version",
    )

    def __init__(self, addr):
        import angr  # pylint:disable=import-outside-toplevel,cyclic-import

        self.parameters: dict[str, Any] = {}
        # angr version and creation time of this decompilation
        self.version: str = angr.__version__
        self.timestamp: int = int(time.time())
        self.addr = addr
        self.cfg: CFGModel | None = None
        # Collection-typed fields default to empty containers rather than None, so serialization never has to
        # distinguish None from empty.
        self.type_constraints: dict[TypeVariable, set[TypeConstraint]] = {}
        self.arg_vvars: dict = {}
        self.func_typevar: TypeVariable | None = None
        self.var_to_typevar: dict = {}
        self.stackvar_max_sizes: dict = {}
        self.stack_offset_typevars: dict = {}
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.clinic: Clinic | None = None
        self.variable_map: VariableMap | None = None
        self.ite_exprs: set[tuple[int, ailment.Expression]] = set()
        self.binop_operators: dict[OpDescriptor, str] = {}
        self.errors: list[str] = []
        self.function_summary: str | None = None
        self.notes: dict[str, DecompilationNote] = {}
        self.max_tv_id: int = 0

    @property
    def local_types(self):
        if self.clinic is None or self.clinic.kb is None or self.addr not in self.clinic.kb.dec_variables:
            return None
        return self.clinic.kb.dec_variables[self.addr].types

    # -----------------------------------------------------------------------------------------------------------------
    # Protobuf serialization. Heavy sub-objects (clinic, codegen) are embedded as already-serialized bytes; AIL-typed
    # top-level fields (arg_vvars, ite_exprs) use the typed messages from ail_types.proto. The four typehoon-typed
    # slots and the ``cfg`` input are not serialized and come back as None.
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
        # Collection fields are never None; an empty collection is simply left unset and parses back to empty.
        if self.arg_vvars:
            msg.arg_vvars.CopyFrom(pack_arg_vvars(self.arg_vvars))
        if self.ite_exprs:
            msg.ite_exprs.CopyFrom(pack_ite_exprs(self.ite_exprs))
        _serialize_binop_operators(self.binop_operators, msg.binop_operators)
        for simvar, size in self.stackvar_max_sizes.items():
            entry = msg.stackvar_max_sizes.add()
            entry.simvar = _simvar_to_bytes(simvar)
            entry.max_size = size

        msg.version = self.version
        msg.timestamp = self.timestamp

        # An unset parameters message means "no recorded parameters"; cache-validity checks treat such a cache as
        # always usable (matching runs with use_cache=False).
        if self.parameters:
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
        cfg=None,
        **_,
    ):
        """Parse a DecompilationCache from a cmessage. Runtime back-references (project, kb, function, cfg) are
        passed through to the embedded Clinic / codegen parsers so the parsed cache is functional for cache-hit
        validity checks. Decompilation variables live on kb.dec_variables."""
        from .notes import DecompilationNote  # pylint:disable=import-outside-toplevel
        from .structured_codegen.c import CStructuredCodeGenerator  # pylint:disable=import-outside-toplevel

        cache = cls(cmsg.addr)
        # cfg is not serialized; reattach from kwargs so cache-validity checks still work.
        cache.cfg = cfg

        if cmsg.HasField("clinic"):
            cache.clinic = Clinic.parse(cmsg.clinic, project=project, kb=kb, function=function, cfg=cfg)
        if cmsg.HasField("codegen"):
            cache.codegen = CStructuredCodeGenerator.parse(cmsg.codegen, project=project, kb=kb, func=function)

        cache.errors = list(cmsg.errors)
        if cmsg.HasField("function_summary"):
            cache.function_summary = cmsg.function_summary
        # Collection fields default to empty (set in __init__); only assign when the message carries content.
        if cmsg.HasField("arg_vvars"):
            cache.arg_vvars = parse_arg_vvars(cmsg.arg_vvars)
        if cmsg.HasField("ite_exprs"):
            cache.ite_exprs = parse_ite_exprs(cmsg.ite_exprs)
        cache.binop_operators = _parse_binop_operators(cmsg.binop_operators)
        cache.stackvar_max_sizes = {_simvar_from_bytes(e.simvar): e.max_size for e in cmsg.stackvar_max_sizes}

        # legacy blobs carry the proto3 defaults ""/0, meaning "unknown"; do not re-stamp them with current values
        cache.version = cmsg.version
        cache.timestamp = cmsg.timestamp
        if cache.codegen is not None:
            # mirror the stamps onto the codegen (a fresh decompile does the same in Decompiler._decompile)
            cache.codegen.version = cache.version
            cache.codegen.timestamp = cache.timestamp

        if cmsg.HasField("parameters"):
            cache.parameters = _parse_parameters(cmsg.parameters)

        cache.notes = {k: DecompilationNote.from_json(v) for k, v in cmsg.notes_json.items()}

        return cache
