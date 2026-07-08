"""
Protobuf serialization helpers for :class:`Clinic`.

Clinic state splits into three buckets:
- **CLEAN**: primitives, sets / lists of ints, dicts of primitives, already-Serializable types (SimVariable variants,
  SRDAModel). Round-tripped natively in :mod:`angr.protos.clinic_pb2`.
- **AIL-typed**: networkx graphs of ailment Blocks, dicts holding ailment.VirtualVariable, etc. Pickled into an
  :class:`AilmentBlob` during the bridging period; will switch to a serde encoding once the ailment Rust port lands.
- **Runtime back-references**: project / kb / function / variable_kb / _cfg / _handlers / _cache / typehoon / _spt.
  Not serialized; reattached at parse time from the caller's kwargs.

``parse_clinic`` uses ``__new__`` to bypass :meth:`Clinic.__init__` because the original constructor runs the full
decompilation pipeline.
"""

from __future__ import annotations
import json
from typing import TYPE_CHECKING

from angr.analyses.decompiler.optimization_pass_registry import name_to_pass, pass_to_name
from angr.analyses.decompiler.stack_item import StackItem, StackItemType
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel
from angr.protos import clinic_pb2
from angr.utils.ailment_blob import pack as ailment_blob_pack, unpack as ailment_blob_unpack

if TYPE_CHECKING:
    from .clinic import Clinic


# ---------------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------------


def _simvar_to_bytes_polymorphic(v) -> bytes:
    """Mirror of the polymorphic SimVariable encoding used by c_serialize: ``b"<ClassName>\\0<proto bytes>"``."""
    return type(v).__name__.encode("ascii") + b"\0" + v.serialize()


def _simvar_from_bytes_polymorphic(b: bytes):
    import angr.sim_variable as sv_mod

    sep = b.index(b"\0")
    cls_name = b[:sep].decode("ascii")
    return getattr(sv_mod, cls_name).parse(b[sep + 1 :])


def _serialize_notes(notes, out_msg) -> None:
    if not notes:
        return
    for k, note in notes.items():
        try:
            content_json = json.dumps(note.content)
        except (TypeError, ValueError):
            content_json = json.dumps(None)
        out_msg[k] = json.dumps(
            {
                "key": note.key,
                "name": note.name,
                "content_json": content_json,
                "level": int(note.level.value),
            }
        )


def _parse_notes(notes_msg) -> dict:
    from angr.analyses.decompiler.notes import DecompilationNote
    from angr.analyses.decompiler.notes.decompilation_note import DecompilationNoteLevel

    result: dict = {}
    for k, blob in notes_msg.items():
        payload = json.loads(blob)
        result[k] = DecompilationNote(
            key=payload["key"],
            name=payload["name"],
            content=json.loads(payload["content_json"]),
            level=DecompilationNoteLevel(payload["level"]),
        )
    return result


def _serialize_pass_classes(classes, out_repeated) -> None:
    if not classes:
        return
    for cls in classes:
        out_repeated.append(pass_to_name(cls))


def _parse_pass_classes(names) -> list[type]:
    return [name_to_pass(n) for n in names]


# ---------------------------------------------------------------------------------------------------------------------
# Serialize
# ---------------------------------------------------------------------------------------------------------------------


def serialize_clinic(clinic: Clinic) -> clinic_pb2.Clinic:
    msg = clinic_pb2.Clinic()

    # Function and arch hints.
    if clinic.function is not None and clinic.function.addr is not None:
        msg.function_addr = clinic.function.addr
    if clinic.flavor is not None:
        msg.flavor = clinic.flavor

    # AIL-typed slots → AilmentBlob.
    msg.graph.CopyFrom(ailment_blob_pack(clinic.graph))
    msg.cc_graph.CopyFrom(ailment_blob_pack(clinic.cc_graph))
    msg.unoptimized_graph.CopyFrom(ailment_blob_pack(clinic.unoptimized_graph))
    msg._ail_graph.CopyFrom(ailment_blob_pack(clinic._ail_graph))
    msg._init_ail_graph.CopyFrom(ailment_blob_pack(clinic._init_ail_graph))
    msg._blocks_by_addr_and_size.CopyFrom(ailment_blob_pack(clinic._blocks_by_addr_and_size))
    msg.arg_vvars.CopyFrom(ailment_blob_pack(clinic.arg_vvars))
    msg._init_arg_vvars.CopyFrom(ailment_blob_pack(clinic._init_arg_vvars))
    msg.func_args.CopyFrom(ailment_blob_pack(clinic.func_args))
    msg._type_hints.CopyFrom(ailment_blob_pack(clinic._type_hints))

    # Already-Serializable sub-objects.
    if clinic.arg_list is not None:
        for sv in clinic.arg_list:
            msg.arg_list.add().payload = _simvar_to_bytes_polymorphic(sv)
    # ``func_ret_var`` is always the same SimVariable(0, "__retvar", "__retvar") sentinel; not serialized — recreated
    # at parse time.
    for sv in clinic.externs:
        msg.externs.add().payload = _simvar_to_bytes_polymorphic(sv)
    if clinic.reaching_definitions is not None:
        msg.reaching_definitions = clinic.reaching_definitions.serialize()

    # CLEAN collections.
    for addr, refs in clinic.data_refs.items():
        lst = msg.data_refs[addr]
        for r in refs:
            ref = lst.refs.add()
            ref.data_addr = r.data_addr
            ref.data_size = r.data_size
            ref.block_addr = r.block_addr
            ref.stmt_idx = r.stmt_idx
            ref.ins_addr = r.ins_addr
            ref.data_type_str = r.data_type_str
    if clinic.vvar_to_vvar is not None:
        for k, v in clinic.vvar_to_vvar.items():
            msg.vvar_to_vvar[k] = v
    msg.secondary_stackvars.extend(sorted(clinic.secondary_stackvars))
    for records in clinic._stackarg_offset_manager.stack_arg_offsets.values():
        for (block_addr, block_idx), ins_addr, offset, size in sorted(
            records, key=lambda r: (r[0][0], -1 if r[0][1] is None else r[0][1], r[1], r[2], r[3])
        ):
            rec = msg.stackarg_offset_records.add()
            rec.block_addr = block_addr
            if block_idx is not None:
                rec.block_idx = block_idx
            rec.ins_addr = ins_addr
            rec.offset = offset
            rec.size = size
    if clinic._removed_vvar_ids is not None:
        msg._removed_vvar_ids_set = True
        msg.removed_vvar_ids.extend(sorted(clinic._removed_vvar_ids))
    msg._preserve_vvar_ids.extend(sorted(clinic._preserve_vvar_ids))
    msg._inline_functions.extend(sorted(f.addr for f in clinic._inline_functions if f.addr is not None))
    for k, v in clinic._inlined_counts.items():
        msg._inlined_counts[k] = v
    msg._inlining_parents.extend(sorted(clinic._inlining_parents))
    if clinic._must_struct is not None:
        msg._must_struct_set = True
        msg._must_struct.extend(sorted(clinic._must_struct))
    if clinic._desired_variables is not None:
        msg._desired_variables_set = True
        msg._desired_variables.extend(sorted(clinic._desired_variables))
    for off, item in clinic.stack_items.items():
        msg.stack_items[off].offset = item.offset
        msg.stack_items[off].size = item.size
        msg.stack_items[off].name = item.name
        msg.stack_items[off].item_type = item.item_type.value
    for src, dst in clinic.edges_to_remove:
        pair = msg.edges_to_remove.add()
        pair.src.addr = src[0]
        if src[1] is not None:
            pair.src.idx = src[1]
        pair.dst.addr = dst[0]
        if dst[1] is not None:
            pair.dst.idx = dst[1]
    msg.copied_var_ids.extend(sorted(clinic.copied_var_ids))
    msg._new_block_addrs.extend(sorted(clinic._new_block_addrs))
    if clinic.entry_node_addr is not None:
        msg.entry_node_addr.addr = clinic.entry_node_addr[0]
        if clinic.entry_node_addr[1] is not None:
            msg.entry_node_addr.idx = clinic.entry_node_addr[1]

    # CLEAN scalars.
    msg.vvar_id_start = clinic.vvar_id_start
    msg._max_stack_depth = clinic._max_stack_depth
    msg._sp_shift = clinic._sp_shift
    msg._max_type_constraints = clinic._max_type_constraints
    msg._type_constraint_set_degradation_threshold = clinic._type_constraint_set_degradation_threshold
    msg._fold_callexprs_into_conditions = clinic._fold_callexprs_into_conditions
    msg._fold_expressions = clinic._fold_expressions
    msg._insert_labels = clinic._insert_labels
    msg._remove_dead_memdefs = clinic._remove_dead_memdefs
    msg._exception_edges = clinic._exception_edges
    msg._sp_tracker_track_memory = clinic._sp_tracker_track_memory
    msg._reset_variable_names = clinic._reset_variable_names
    msg._rewrite_ites_to_diamonds = clinic._rewrite_ites_to_diamonds
    msg._flatten_args = clinic._flatten_args
    msg._semvar_naming = clinic._semvar_naming
    msg._force_loop_single_exit = clinic._force_loop_single_exit
    msg._refine_loops_with_single_successor = clinic._refine_loops_with_single_successor
    msg._register_save_areas_removed = clinic._register_save_areas_removed
    msg._rewrite_ites_to_diamond_max_cases = clinic._rewrite_ites_to_diamond_max_cases
    msg._expose_loop_head_backedges = clinic._expose_loop_head_backedges
    msg._constrain_callee_prototypes = clinic._constrain_callee_prototypes

    msg._mode = clinic._mode.value
    msg._start_stage = clinic._start_stage.value
    msg._end_stage = clinic._end_stage.value
    msg._skip_stages.extend(s.value for s in clinic._skip_stages)

    # Pass class refs.
    if clinic.peephole_optimizations is not None:
        msg._peephole_optimizations_set = True
        _serialize_pass_classes(list(clinic.peephole_optimizations), msg.peephole_optimizations)
    if clinic._typehoon_cls is not None:
        msg._typehoon_cls = pass_to_name(clinic._typehoon_cls) if clinic._typehoon_cls.__module__ != "builtins" else ""
        # ``_typehoon_cls`` is normally the Typehoon class itself, not a pass; we still encode via FQN for symmetry.

    # Notes.
    _serialize_notes(clinic.notes, msg.notes_json)
    return msg


# ---------------------------------------------------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------------------------------------------------


def parse_clinic(msg: clinic_pb2.Clinic, *, project=None, kb=None, function=None, variable_kb=None, cfg=None) -> Clinic:
    """Bypasses :meth:`Clinic.__init__` (which runs the analysis) and reconstructs the instance directly. Runtime
    back-references — project / kb / function / variable_kb / _cfg — come from kwargs.

    If ``function`` is None and ``kb`` is provided, the function is resolved by address from the cmessage."""
    from .clinic import Clinic, ClinicMode, ClinicStage
    from angr.knowledge_plugins.key_definitions import atoms  # noqa: F401  (needed for unpickled _type_hints)
    import importlib

    clinic = Clinic.__new__(Clinic)

    # Resolve function from address if not provided.
    if function is None and kb is not None and msg.HasField("function_addr"):
        function = kb.functions.function(msg.function_addr)

    # Initialize back-references and Analysis-base state. We bypass Analysis.__init__ so set the bare minimum.
    clinic.project = project
    clinic.kb = kb
    clinic.function = function
    clinic._cache = None
    clinic._ail_manager = None
    clinic._spt = None
    clinic.typehoon = None
    clinic._optimization_passes = []
    clinic.optimization_scratch = {}

    # AIL-typed slots.
    clinic.graph = ailment_blob_unpack(msg.graph) if msg.HasField("graph") else None
    clinic.cc_graph = ailment_blob_unpack(msg.cc_graph) if msg.HasField("cc_graph") else None
    clinic.unoptimized_graph = ailment_blob_unpack(msg.unoptimized_graph) if msg.HasField("unoptimized_graph") else None
    clinic._ail_graph = ailment_blob_unpack(msg._ail_graph) if msg.HasField("_ail_graph") else None
    clinic._init_ail_graph = ailment_blob_unpack(msg._init_ail_graph) if msg.HasField("_init_ail_graph") else None
    clinic._blocks_by_addr_and_size = (
        ailment_blob_unpack(msg._blocks_by_addr_and_size) if msg.HasField("_blocks_by_addr_and_size") else {}
    )
    clinic.arg_vvars = ailment_blob_unpack(msg.arg_vvars) if msg.HasField("arg_vvars") else None
    clinic._init_arg_vvars = ailment_blob_unpack(msg._init_arg_vvars) if msg.HasField("_init_arg_vvars") else None
    clinic.func_args = ailment_blob_unpack(msg.func_args) if msg.HasField("func_args") else None
    clinic._type_hints = ailment_blob_unpack(msg._type_hints) if msg.HasField("_type_hints") else []

    # Already-Serializable sub-objects.
    clinic.arg_list = [_simvar_from_bytes_polymorphic(e.payload) for e in msg.arg_list] if msg.arg_list else None
    from angr.sim_variable import SimVariable

    clinic.func_ret_var = SimVariable(0, "__retvar", "__retvar")
    clinic.externs = {_simvar_from_bytes_polymorphic(e.payload) for e in msg.externs}
    clinic.reaching_definitions = (
        SRDAModel.parse(msg.reaching_definitions, arch=project.arch if project is not None else None)
        if msg.reaching_definitions
        else None
    )

    # Variable_kb / cfg back-references.
    clinic.variable_kb = variable_kb
    clinic._cfg = cfg

    # Flavor.
    clinic.flavor = msg.flavor if msg.HasField("flavor") else "pseudocode"

    # CLEAN collections.
    from .clinic import DataRefDesc

    clinic.data_refs = {
        addr: [
            DataRefDesc(
                data_addr=r.data_addr,
                data_size=r.data_size,
                block_addr=r.block_addr,
                stmt_idx=r.stmt_idx,
                ins_addr=r.ins_addr,
                data_type_str=r.data_type_str,
            )
            for r in lst.refs
        ]
        for addr, lst in msg.data_refs.items()
    }
    clinic.vvar_to_vvar = dict(msg.vvar_to_vvar) if msg.vvar_to_vvar else None
    clinic.secondary_stackvars = set(msg.secondary_stackvars)
    from .stackarg_offset_manager import StackArgOffsetManager

    clinic._stackarg_offset_manager = StackArgOffsetManager(project.arch.bits if project is not None else 64)
    for rec in msg.stackarg_offset_records:
        block_idx = rec.block_idx if rec.HasField("block_idx") else None
        clinic._stackarg_offset_manager.stack_arg_offsets.setdefault(rec.offset, set()).add(
            ((rec.block_addr, block_idx), rec.ins_addr, rec.offset, rec.size)
        )
    # stackoff_to_vvars / all_stackarg_vvars are derived from the SRDA model; recompute rather than serialize.
    if clinic.reaching_definitions is not None:
        clinic._stackarg_offset_manager.update_stackoff_vvars(clinic.reaching_definitions)
    clinic._removed_vvar_ids = set(msg.removed_vvar_ids) if msg._removed_vvar_ids_set else None
    clinic._preserve_vvar_ids = set(msg._preserve_vvar_ids)
    clinic._inline_functions = (
        {kb.functions.function(addr) for addr in msg._inline_functions if kb.functions.function(addr) is not None}
        if kb is not None
        else set()
    )
    clinic._inlined_counts = dict(msg._inlined_counts)
    clinic._inlining_parents = set(msg._inlining_parents)
    clinic._must_struct = set(msg._must_struct) if msg._must_struct_set else None
    clinic._desired_variables = set(msg._desired_variables) if msg._desired_variables_set else None
    clinic.stack_items = {
        off: StackItem(item.offset, item.size, item.name, StackItemType(item.item_type))
        for off, item in msg.stack_items.items()
    }
    clinic.edges_to_remove = [
        (
            (pair.src.addr, pair.src.idx if pair.src.HasField("idx") else None),
            (pair.dst.addr, pair.dst.idx if pair.dst.HasField("idx") else None),
        )
        for pair in msg.edges_to_remove
    ]
    clinic.copied_var_ids = set(msg.copied_var_ids)
    clinic._new_block_addrs = set(msg._new_block_addrs)
    clinic.entry_node_addr = (
        (msg.entry_node_addr.addr, msg.entry_node_addr.idx if msg.entry_node_addr.HasField("idx") else None)
        if msg.HasField("entry_node_addr")
        else None
    )

    # CLEAN scalars.
    clinic.vvar_id_start = msg.vvar_id_start
    clinic._max_stack_depth = msg._max_stack_depth
    clinic._sp_shift = msg._sp_shift
    clinic._max_type_constraints = msg._max_type_constraints
    clinic._type_constraint_set_degradation_threshold = msg._type_constraint_set_degradation_threshold
    clinic._fold_callexprs_into_conditions = msg._fold_callexprs_into_conditions
    clinic._fold_expressions = msg._fold_expressions
    clinic._insert_labels = msg._insert_labels
    clinic._remove_dead_memdefs = msg._remove_dead_memdefs
    clinic._exception_edges = msg._exception_edges
    clinic._sp_tracker_track_memory = msg._sp_tracker_track_memory
    clinic._reset_variable_names = msg._reset_variable_names
    clinic._rewrite_ites_to_diamonds = msg._rewrite_ites_to_diamonds
    clinic._flatten_args = msg._flatten_args
    clinic._semvar_naming = msg._semvar_naming
    clinic._force_loop_single_exit = msg._force_loop_single_exit
    clinic._refine_loops_with_single_successor = msg._refine_loops_with_single_successor
    clinic._register_save_areas_removed = msg._register_save_areas_removed
    clinic._rewrite_ites_to_diamond_max_cases = msg._rewrite_ites_to_diamond_max_cases
    clinic._expose_loop_head_backedges = msg._expose_loop_head_backedges
    clinic._constrain_callee_prototypes = msg._constrain_callee_prototypes

    clinic._mode = ClinicMode(msg._mode) if msg._mode in {m.value for m in ClinicMode} else ClinicMode.DECOMPILE
    clinic._start_stage = ClinicStage(msg._start_stage)
    clinic._end_stage = ClinicStage(msg._end_stage)
    clinic._skip_stages = tuple(ClinicStage(s) for s in msg._skip_stages)

    # Pass class refs.
    if msg._peephole_optimizations_set:
        clinic.peephole_optimizations = _parse_pass_classes(msg.peephole_optimizations)
    else:
        clinic.peephole_optimizations = None
    if msg._typehoon_cls:
        # _typehoon_cls is the Typehoon class itself (not a registered pass). Resolve directly by FQN.
        module_name, _, cls_name = msg._typehoon_cls.rpartition(".")
        clinic._typehoon_cls = getattr(importlib.import_module(module_name), cls_name)
    else:
        from angr.analyses.typehoon.typehoon import Typehoon

        clinic._typehoon_cls = Typehoon

    # Notes.
    clinic.notes = _parse_notes(msg.notes_json)

    # The remainder of the public Clinic surface that isn't part of the serialized state — set sensible defaults so
    # attribute access doesn't crash.
    from .variable_map import VariableMap

    clinic.static_vvars = {}
    clinic.static_buffers = {}
    clinic._func_graph = None
    clinic.variable_map = VariableMap()

    return clinic
