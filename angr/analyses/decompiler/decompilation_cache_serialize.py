"""
Protobuf serialization helpers for :class:`DecompilationCache`.

This module ties the per-step serialization built up over steps 1-5 together. It does not introduce any new schema
beyond what's in ``decompilation_cache.proto``; it just wires up the cmsg ↔ Python translation for the cache and its
``parameters`` sub-dict.

Conventions:
- Heavy sub-objects (``clinic``, ``codegen``) are embedded as already-serialized bytes (each manages its own format).
- AIL-typed top-level slots (``arg_vvars``, ``ite_exprs``) use the typed messages from ``ail_types.proto``.
- ``cfg`` and ``variable_kb`` are intentionally not serialized — they come from the parent Project.
- The 4 typehoon-typed slots are skipped entirely (typehoon is out of scope for now).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from angr.analyses.decompiler.optimization_pass_registry import name_to_pass, pass_to_name
from angr.protos import decompilation_cache_pb2
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

if TYPE_CHECKING:
    from .decompilation_cache import DecompilationCache


# ---------------------------------------------------------------------------------------------------------------------
# SimVariable polymorphic encoding (same shape as elsewhere)
# ---------------------------------------------------------------------------------------------------------------------


def _simvar_to_bytes(v) -> bytes:
    return type(v).__name__.encode("ascii") + b"\0" + v.serialize()


def _simvar_from_bytes(b: bytes):
    import angr.sim_variable as sv_mod

    sep = b.index(b"\0")
    return getattr(sv_mod, b[:sep].decode("ascii")).parse(b[sep + 1 :])


def _serialize_binop_operators(binop_operators, out_msg, set_flag=None) -> None:
    if binop_operators is None:
        return
    if set_flag is not None:
        setattr(set_flag[0], set_flag[1], True)
    for op_desc, value in binop_operators.items():
        entry = out_msg.add()
        entry.key.CopyFrom(op_desc.serialize_to_cmessage())
        entry.value = value


def _parse_binop_operators(entries):
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor

    return {OpDescriptor.parse_from_cmessage(e.key): e.value for e in entries}


# ---------------------------------------------------------------------------------------------------------------------
# DecompilationParameters
# ---------------------------------------------------------------------------------------------------------------------


def _serialize_parameters(params: dict, out_msg) -> None:
    """Translate the 14-key parameters dict into a DecompilationParameters cmessage."""
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
    from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION

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


# ---------------------------------------------------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------------------------------------------------


def serialize_cache(cache: DecompilationCache) -> decompilation_cache_pb2.DecompilationCache:
    msg = decompilation_cache_pb2.DecompilationCache(addr=cache.addr)

    if cache.clinic is not None:
        msg.clinic = cache.clinic.serialize()
    if cache.codegen is not None:
        msg.codegen = cache.codegen.serialize()

    msg.errors.extend(cache.errors)
    if cache.function_summary is not None:
        msg.function_summary = cache.function_summary
    if cache.arg_vvars is not None:
        msg.arg_vvars.CopyFrom(pack_arg_vvars(cache.arg_vvars))
    if cache.ite_exprs is not None:
        msg.ite_exprs.CopyFrom(pack_ite_exprs(cache.ite_exprs))
    if cache.binop_operators is not None:
        msg._binop_operators_set = True
        _serialize_binop_operators(cache.binop_operators, msg.binop_operators)
    if cache.stackvar_max_sizes is not None:
        msg._stackvar_max_sizes_set = True
        for simvar, size in cache.stackvar_max_sizes.items():
            entry = msg.stackvar_max_sizes.add()
            entry.simvar = _simvar_to_bytes(simvar)
            entry.max_size = size

    msg.version = cache.version
    msg.timestamp = cache.timestamp

    if cache.parameters:
        msg.parameters_set = True
        _serialize_parameters(cache.parameters, msg.parameters)

    for k, note in cache.notes.items():
        msg.notes_json[k] = note.to_json()

    return msg


def parse_cache(
    cmsg,
    *,
    project=None,
    kb=None,
    function=None,
    variable_kb=None,
    cfg=None,
    **_,
):
    """Parse a DecompilationCache from a cmessage. Runtime back-references (project, kb, function, variable_kb, cfg)
    are passed through to the embedded Clinic / codegen parsers so the parsed cache is functional for cache-hit
    validity checks."""
    from .clinic import Clinic
    from .decompilation_cache import DecompilationCache
    from .notes import DecompilationNote
    from .structured_codegen.c import CStructuredCodeGenerator

    cache = DecompilationCache(cmsg.addr)
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

    if cmsg.parameters_set:
        cache.parameters = _parse_parameters(cmsg.parameters)

    cache.notes = {k: DecompilationNote.from_json(v) for k, v in cmsg.notes_json.items()}

    return cache
