from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, Literal, overload

from angr.ailment import Address
from angr.ailment.expression import Tmp, VirtualVariable
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions import Definition, atoms
from angr.protos import srda_model_pb2
from angr.serializable import Serializable
from angr.utils.ailment_blob import pack as ailment_blob_pack, unpack as ailment_blob_unpack

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function_manager import FunctionManager


class SRDAModel(Serializable):
    """
    The model for SRDA.
    """

    def __init__(
        self,
        func_graph,
        func_args,
        arch,
        platform: str | None = None,
        language: str | None = None,
        variable_map=None,
        functions: FunctionManager | None = None,
    ):
        self.func_graph = func_graph
        self.func_args = func_args
        self.arch = arch
        self.platform = platform
        self.language = language
        self.variable_map = variable_map
        self.functions = functions
        self.varid_to_vvar: dict[int, VirtualVariable] = {}
        self.all_vvar_definitions: dict[int, AILCodeLocation] = {}
        self.all_vvar_uses: dict[int, list[tuple[VirtualVariable | None, AILCodeLocation]]] = defaultdict(list)
        self.all_tmp_definitions: dict[Address, dict[atoms.Tmp, int]] = defaultdict(dict)
        self.all_tmp_uses: dict[Address, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)
        self.phi_vvar_ids: set[int] = set()
        self.phivarid_to_varids_with_unknown: dict[int, set[int | None]] = {}
        self.phivarid_to_varids: dict[int, set[int]] = {}
        self.vvar_uses_by_loc: dict[AILCodeLocation, list[int]] = {}

    def add_vvar_use(self, vvar_id: int, expr: VirtualVariable | None, loc: AILCodeLocation) -> None:
        self.all_vvar_uses[vvar_id].append((expr, loc))
        if loc not in self.vvar_uses_by_loc:
            self.vvar_uses_by_loc[loc] = []
        self.vvar_uses_by_loc[loc].append(vvar_id)

    def update_after_block_edits(self, edited_blocks) -> None:
        """
        Incrementally update the model after the statements of ``edited_blocks`` were edited *in place* (statement
        indices preserved, e.g. by replacing removed statements with ``NoOp`` placeholders). vvar definitions and
        explicit vvar uses inside the edited blocks are recomputed from the edited blocks; implicit uses (``expr is
        None``, e.g. call-site argument registers) and all unedited blocks are left untouched.

        This is designed to be equivalent to a full SRDA rebuild on the edited graph for the kind of edits performed
        by dead-assignment removal: statements are only removed (turned into NoOp) or rewritten in place, never
        inserted or reordered, and removed vvars are dead (so they are never used elsewhere, including by phi nodes or
        implicit call-site uses). Tmp tracking is not updated (AILSimplifier does not track tmps).
        """

        from angr.utils.ssa import get_vvar_deflocs, get_vvar_uselocs  # pylint:disable=import-outside-toplevel

        edited_blocks = list(edited_blocks)
        block_keys = {(b.addr, b.idx) for b in edited_blocks}

        def in_edited(loc: AILCodeLocation) -> bool:
            return (loc.block_addr, loc.block_idx) in block_keys

        # --- definitions ---
        new_phi: dict[int, set[int | None]] = {}
        # check_extra_defs is disabled because we scan only a subset of the graph's blocks here
        new_deflocs = get_vvar_deflocs(edited_blocks, phi_vvars=new_phi, check_extra_defs=False)

        old_def_vids = {vid for vid, loc in self.all_vvar_definitions.items() if in_edited(loc)}
        for vid in old_def_vids - set(new_deflocs):
            # this definition no longer exists; keep its uses for now (if the vvar is still used elsewhere it becomes
            # a used-but-undefined extern vvar, reconciled below)
            self.varid_to_vvar.pop(vid, None)
            self.all_vvar_definitions.pop(vid, None)
            self.phi_vvar_ids.discard(vid)
            self.phivarid_to_varids.pop(vid, None)
            self.phivarid_to_varids_with_unknown.pop(vid, None)

        # surviving defs keep their (index-stable) location; refresh vvar and phi info from the rescan
        for vid, (vvar, defloc) in new_deflocs.items():
            self.varid_to_vvar[vid] = vvar
            self.all_vvar_definitions[vid] = defloc
            if vid in new_phi:
                src = new_phi[vid]
                self.phi_vvar_ids.add(vid)
                self.phivarid_to_varids_with_unknown[vid] = src
                self.phivarid_to_varids[vid] = {x for x in src if x is not None} if None in src else set(src)  # type: ignore
            else:
                self.phi_vvar_ids.discard(vid)
                self.phivarid_to_varids.pop(vid, None)
                self.phivarid_to_varids_with_unknown.pop(vid, None)

        # --- explicit uses ---
        # drop explicit uses (expr is not None) located in edited blocks; keep implicit uses (expr is None)
        for vid in list(self.all_vvar_uses):
            entries = self.all_vvar_uses[vid]
            kept = [(e, loc) for e, loc in entries if e is None or not in_edited(loc)]
            if len(kept) != len(entries):
                if kept:
                    self.all_vvar_uses[vid] = kept
                else:
                    del self.all_vvar_uses[vid]
        # re-add the recomputed explicit uses for the edited blocks
        for vid, uses in get_vvar_uselocs(edited_blocks).items():
            for expr, loc in uses:
                self.all_vvar_uses[vid].append((expr, loc))

        # --- rebuild vvar_uses_by_loc for affected locations from the updated all_vvar_uses ---
        for loc in [loc for loc in self.vvar_uses_by_loc if in_edited(loc)]:
            del self.vvar_uses_by_loc[loc]
        for vid, entries in self.all_vvar_uses.items():
            for _expr, loc in entries:
                if in_edited(loc):
                    if loc not in self.vvar_uses_by_loc:
                        self.vvar_uses_by_loc[loc] = []
                    self.vvar_uses_by_loc[loc].append(vid)

        # --- reconcile extern (used-but-undefined) definitions to match a full rebuild ---
        # A vvar that is explicitly used but has no real definition (e.g. its defining statement was just removed) gets
        # a synthetic extern definition; an extern, non-argument vvar that is no longer explicitly used is dropped.
        func_arg_ids = {vvar.varid for vvar in self.func_args} if self.func_args else set()
        explicit_use_repr: dict[int, VirtualVariable] = {}
        for vid, entries in self.all_vvar_uses.items():
            for expr, _loc in entries:
                if expr is not None:
                    explicit_use_repr[vid] = expr
                    break
        for vid, expr in explicit_use_repr.items():
            if vid not in self.all_vvar_definitions:
                self.varid_to_vvar[vid] = expr
                self.all_vvar_definitions[vid] = AILCodeLocation.make_extern(vid)
        for vid in [
            vid
            for vid, loc in self.all_vvar_definitions.items()
            if loc.is_extern and vid not in func_arg_ids and vid not in explicit_use_repr
        ]:
            self.varid_to_vvar.pop(vid, None)
            self.all_vvar_definitions.pop(vid, None)
            self.all_vvar_uses.pop(vid, None)
            self.phi_vvar_ids.discard(vid)
            self.phivarid_to_varids.pop(vid, None)
            self.phivarid_to_varids_with_unknown.pop(vid, None)

    def canonical_form(self):
        """
        An order-insensitive snapshot of the model's vvar-keyed data, for asserting equivalence between an
        incrementally-updated model and a freshly-rebuilt one (used by the incremental-update verification harness).
        """
        return (
            set(self.varid_to_vvar),
            dict(self.all_vvar_definitions),
            {
                vid: Counter((e.varid if e is not None else None, loc) for e, loc in lst)
                for vid, lst in self.all_vvar_uses.items()
                if lst
            },
            set(self.phi_vvar_ids),
            {k: frozenset(v) for k, v in self.phivarid_to_varids.items()},
            {k: frozenset(v) for k, v in self.phivarid_to_varids_with_unknown.items()},
            {loc: Counter(vids) for loc, vids in self.vvar_uses_by_loc.items() if vids},
        )

    @property
    def all_definitions(self) -> Iterator[Definition[atoms.VirtualVariable, AILCodeLocation]]:
        for vvar_id, defloc in self.all_vvar_definitions.items():
            vvar = self.varid_to_vvar[vvar_id]
            yield Definition(atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident), defloc)

    def is_phi_vvar_id(self, idx: int) -> bool:
        return idx in self.phi_vvar_ids

    def get_all_definitions(
        self, block_loc: AILCodeLocation
    ) -> set[Definition[atoms.VirtualVariable | atoms.Tmp, AILCodeLocation]]:
        s: set[Definition[atoms.VirtualVariable | atoms.Tmp, AILCodeLocation]] = set()
        for vvar_id, codeloc in self.all_vvar_definitions.items():
            vvar = self.varid_to_vvar[vvar_id]
            if codeloc.addr == block_loc.addr and codeloc.block_idx == block_loc.block_idx:
                s.add(Definition(atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident), codeloc))
        s.update(self.get_all_tmp_definitions((block_loc.addr, block_loc.block_idx)))  # type: ignore
        return s

    def get_all_tmp_definitions(self, block_loc: Address) -> set[Definition[atoms.Tmp, AILCodeLocation]]:
        s = set()
        for tmp_atom, stmt_idx in self.all_tmp_definitions[block_loc].items():
            s.add(Definition(tmp_atom, AILCodeLocation(block_loc[0], block_loc[1], stmt_idx)))
        return s

    @overload
    def get_uses_by_location(
        self, loc: AILCodeLocation, exprs: Literal[True]
    ) -> set[tuple[Definition[atoms.VirtualVariable, AILCodeLocation], Any | None]]: ...

    @overload
    def get_uses_by_location(
        self, loc: AILCodeLocation, exprs: Literal[False] = ...
    ) -> set[Definition[atoms.VirtualVariable, AILCodeLocation]]: ...

    def get_uses_by_location(
        self, loc: AILCodeLocation, exprs: bool = False
    ) -> (
        set[Definition[atoms.VirtualVariable, AILCodeLocation]]
        | set[tuple[Definition[atoms.VirtualVariable, AILCodeLocation], Any | None]]
    ):
        """
        Retrieve all definitions that are used at a given location.

        :param loc:     The code location.
        :return:        A set of definitions that are used at the given location.
        """
        if exprs:
            def_with_exprs: set[tuple[Definition[atoms.VirtualVariable, AILCodeLocation], Any]] = set()
            if loc not in self.vvar_uses_by_loc:
                return def_with_exprs
            for vvar_id in self.vvar_uses_by_loc[loc]:
                vvar = self.varid_to_vvar[vvar_id]
                def_with_exprs.add(
                    (
                        Definition(
                            atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident),
                            self.all_vvar_definitions[vvar_id],
                        ),
                        vvar,
                    )
                )
            return def_with_exprs

        defs: set[Definition[atoms.VirtualVariable, AILCodeLocation]] = set()
        if loc not in self.vvar_uses_by_loc:
            return defs
        for vvar_id in self.vvar_uses_by_loc[loc]:
            vvar = self.varid_to_vvar[vvar_id]
            defs.add(
                Definition(
                    atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident),
                    self.all_vvar_definitions[vvar_id],
                )
            )
        return defs

    def get_vvar_uses(self, obj: VirtualVariable | atoms.VirtualVariable) -> set[AILCodeLocation]:
        if obj.varid in self.all_vvar_uses:
            return {loc for _, loc in self.all_vvar_uses[obj.varid]}
        return set()

    def get_vvar_uses_with_expr(
        self, obj: VirtualVariable | atoms.VirtualVariable
    ) -> set[tuple[VirtualVariable | None, AILCodeLocation]]:
        if obj.varid in self.all_vvar_uses:
            return set(self.all_vvar_uses[obj.varid])
        return set()

    def get_tmp_uses(self, obj: atoms.Tmp, block_loc: Address) -> set[AILCodeLocation]:
        if block_loc not in self.all_tmp_uses:
            return set()
        if obj not in self.all_tmp_uses[block_loc]:
            return set()
        s = set()
        for _, stmt_idx in self.all_tmp_uses[block_loc][obj]:
            s.add(AILCodeLocation(block_loc[0], block_loc[1], stmt_idx))
        return s

    def get_uses_by_def(
        self, def_: Definition[atoms.Tmp | atoms.VirtualVariable, AILCodeLocation]
    ) -> set[AILCodeLocation]:
        if isinstance(def_.atom, atoms.Tmp):
            return self.get_tmp_uses(def_.atom, (def_.codeloc.addr, def_.codeloc.block_idx))
        if isinstance(def_.atom, atoms.VirtualVariable):
            return self.get_vvar_uses(def_.atom)
        return set()

    # Ailment-typed slots (func_graph, func_args, varid_to_vvar, all_vvar_uses, all_tmp_uses) are pickled into an
    # AilmentBlob during the bridging period; arch is reattached from the parent Project at parse time.

    @classmethod
    def _get_cmsg(cls):
        return srda_model_pb2.SRDAModel()

    def serialize_to_cmessage(self):
        msg = srda_model_pb2.SRDAModel()
        if self.arch is not None:
            msg.arch_name = self.arch.name

        msg.func_graph.CopyFrom(ailment_blob_pack(self.func_graph))
        msg.func_args.CopyFrom(ailment_blob_pack(self.func_args))
        msg.varid_to_vvar.CopyFrom(ailment_blob_pack(self.varid_to_vvar))
        msg.all_vvar_uses.CopyFrom(ailment_blob_pack(dict(self.all_vvar_uses)))
        msg.all_tmp_uses.CopyFrom(ailment_blob_pack(dict(self.all_tmp_uses)))

        for varid, codeloc in self.all_vvar_definitions.items():
            entry = msg.all_vvar_definitions.add()
            entry.varid = varid
            entry.codeloc.CopyFrom(codeloc.serialize_to_cmessage())

        for block_loc, tmp_defs in self.all_tmp_definitions.items():
            row = msg.all_tmp_definitions.add()
            row.block_addr = block_loc[0]
            if block_loc[1] is not None:
                row.block_idx = block_loc[1]
            for tmp_atom, stmt_idx in tmp_defs.items():
                def_entry = row.defs.add()
                def_entry.tmp.CopyFrom(tmp_atom._serialize_inner())
                def_entry.stmt_idx = stmt_idx

        msg.phi_vvar_ids.extend(sorted(self.phi_vvar_ids))

        for phi_varid, sources in self.phivarid_to_varids_with_unknown.items():
            entry = msg.phivarid_to_varids_with_unknown.add()
            entry.phi_varid = phi_varid
            entry.has_unknown = None in sources
            entry.source_varids.extend(sorted(s for s in sources if s is not None))

        for phi_varid, sources in self.phivarid_to_varids.items():
            entry = msg.phivarid_to_varids.add()
            entry.phi_varid = phi_varid
            entry.source_varids.extend(sorted(sources))

        for loc, varids in self.vvar_uses_by_loc.items():
            entry = msg.vvar_uses_by_loc.add()
            entry.loc.CopyFrom(loc.serialize_to_cmessage())
            entry.varids.extend(varids)

        return msg

    @classmethod
    def parse_from_cmessage(cls, cmsg, *, arch=None, **kwargs):  # pylint:disable=arguments-differ
        func_graph = ailment_blob_unpack(cmsg.func_graph) if cmsg.HasField("func_graph") else None
        func_args = ailment_blob_unpack(cmsg.func_args) if cmsg.HasField("func_args") else None
        model = cls(func_graph, func_args, arch)

        if cmsg.HasField("varid_to_vvar"):
            model.varid_to_vvar = ailment_blob_unpack(cmsg.varid_to_vvar)
        if cmsg.HasField("all_vvar_uses"):
            unpacked = ailment_blob_unpack(cmsg.all_vvar_uses)
            model.all_vvar_uses = defaultdict(list, unpacked)
        if cmsg.HasField("all_tmp_uses"):
            unpacked = ailment_blob_unpack(cmsg.all_tmp_uses)
            model.all_tmp_uses = defaultdict(dict, unpacked)

        model.all_vvar_definitions = {
            entry.varid: AILCodeLocation.parse_from_cmessage(entry.codeloc) for entry in cmsg.all_vvar_definitions
        }

        all_tmp_definitions: dict[Address, dict[atoms.Tmp, int]] = defaultdict(dict)
        for row in cmsg.all_tmp_definitions:
            block_idx = row.block_idx if row.HasField("block_idx") else None
            block_loc: Address = (row.block_addr, block_idx)
            for def_entry in row.defs:
                tmp_atom = atoms.Tmp._parse_from_inner(def_entry.tmp)
                all_tmp_definitions[block_loc][tmp_atom] = def_entry.stmt_idx
        model.all_tmp_definitions = all_tmp_definitions

        model.phi_vvar_ids = set(cmsg.phi_vvar_ids)

        model.phivarid_to_varids_with_unknown = {
            entry.phi_varid: ({*entry.source_varids} | ({None} if entry.has_unknown else set()))
            for entry in cmsg.phivarid_to_varids_with_unknown
        }
        model.phivarid_to_varids = {entry.phi_varid: set(entry.source_varids) for entry in cmsg.phivarid_to_varids}
        model.vvar_uses_by_loc = {
            AILCodeLocation.parse_from_cmessage(entry.loc): list(entry.varids) for entry in cmsg.vvar_uses_by_loc
        }

        return model
