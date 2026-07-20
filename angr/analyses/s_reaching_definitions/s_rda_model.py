from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, Literal, overload

from angr.ailment import Address
from angr.ailment.block import Block
from angr.ailment.expression import Tmp, VirtualVariable
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions import Definition, atoms
from angr.protos import srda_model_pb2
from angr.serializable import Serializable
from angr.utils.ail_serialization import pack_graph, pack_vvar_set, parse_graph, parse_vvar_set
from angr.utils.ssa import get_tmp_deflocs, get_tmp_uselocs, get_vvar_deflocs, get_vvar_uselocs

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

    # Only the scan inputs (func_graph, func_args) are serialized; every derived field (varid_to_vvar,
    # all_vvar_definitions, all_vvar_uses, all_tmp_definitions, all_tmp_uses, phi bookkeeping, vvar_uses_by_loc) is
    # reconstructed at parse time by re-running the linear scan (``populate_model``) over the deserialized graph.
    # arch is reattached from the parent Project at parse time.

    @classmethod
    def _get_cmsg(cls):
        return srda_model_pb2.SRDAModel()

    def serialize_to_cmessage(self):
        msg = srda_model_pb2.SRDAModel()
        if self.arch is not None:
            msg.arch_name = self.arch.name

        if self.func_graph is not None:
            msg.func_graph.CopyFrom(pack_graph(self.func_graph))
        if self.func_args is not None:
            msg.func_args.CopyFrom(pack_vvar_set(self.func_args))
        msg.track_tmps = bool(self.all_tmp_definitions) or bool(self.all_tmp_uses)

        return msg

    @classmethod
    def parse_from_cmessage(cls, cmsg, *, arch=None, **kwargs):  # pylint:disable=arguments-differ
        func_graph = parse_graph(cmsg.func_graph) if cmsg.HasField("func_graph") else None
        func_args = parse_vvar_set(cmsg.func_args) if cmsg.HasField("func_args") else None
        model = cls(func_graph, func_args, arch)

        if func_graph is not None:
            blocks = {(block.addr, block.idx): block for block in func_graph}
            populate_model(model, blocks, func_args, fix_undefined_vvars=True, track_tmps=cmsg.track_tmps)

        return model


def populate_model(
    model: SRDAModel,
    blocks: dict[tuple[int, int | None], Block],
    func_args: set[VirtualVariable] | None,
    *,
    fix_undefined_vvars: bool = True,
    track_tmps: bool = False,
) -> None:
    """Populate the scan-derived part of an SRDAModel (vvar/tmp definitions and uses, phi bookkeeping) with a linear
    scan over ``blocks``. This is the shared core of :class:`SReachingDefinitionsAnalysis` and of SRDAModel
    deserialization, which reconstructs these fields instead of serializing them."""

    phi_vvars: dict[int, set[int | None]] = {}
    # find all vvar definitions
    vvar_deflocs = get_vvar_deflocs(blocks.values(), phi_vvars=phi_vvars)
    # find all explicit vvar uses
    vvar_uselocs = get_vvar_uselocs(blocks.values())

    # update vvar definitions using function arguments
    if func_args:
        for vvar in func_args:
            if vvar.varid not in vvar_deflocs:
                vvar_deflocs[vvar.varid] = vvar, AILCodeLocation.make_extern(vvar.varid)
        model.func_args = func_args

    # update model
    for vvar_id, (vvar, defloc) in vvar_deflocs.items():
        model.varid_to_vvar[vvar_id] = vvar
        model.all_vvar_definitions[vvar_id] = defloc
        if vvar_id in vvar_uselocs:
            for useloc in vvar_uselocs[vvar_id]:
                model.add_vvar_use(vvar_id, *useloc)

    model.phi_vvar_ids = set(phi_vvars)
    model.phivarid_to_varids = {}
    for vvar_id, src_vvars in phi_vvars.items():
        model.phivarid_to_varids_with_unknown[vvar_id] = src_vvars
        model.phivarid_to_varids[vvar_id] = (  # type: ignore
            {vvar_id for vvar_id in src_vvars if vvar_id is not None} if None in src_vvars else src_vvars
        )

    if fix_undefined_vvars:
        # fix register definitions for arguments
        defined_vvarids = set(vvar_deflocs)
        undefined_vvarids = set(vvar_uselocs.keys()).difference(defined_vvarids)
        for vvar_id in undefined_vvarids:
            used_vvar = next(iter(vvar_uselocs[vvar_id]))[0]
            model.varid_to_vvar[vvar_id] = used_vvar
            model.all_vvar_definitions[vvar_id] = AILCodeLocation.make_extern(vvar_id)
            if vvar_id in vvar_uselocs:
                for vvar_useloc in vvar_uselocs[vvar_id]:
                    model.add_vvar_use(vvar_id, *vvar_useloc)

    if track_tmps:
        # track tmps
        tmp_deflocs = get_tmp_deflocs(blocks.values())
        # find all vvar uses
        tmp_uselocs = get_tmp_uselocs(blocks.values())

        # update model
        for block_loc, d in tmp_deflocs.items():
            for tmp_atom, stmt_idx in d.items():
                model.all_tmp_definitions[block_loc][tmp_atom] = stmt_idx

                if tmp_atom in tmp_uselocs[block_loc]:
                    for tmp_at_use, use_stmt_idx in tmp_uselocs[block_loc][tmp_atom]:
                        if tmp_atom not in model.all_tmp_uses[block_loc]:
                            model.all_tmp_uses[block_loc][tmp_atom] = set()
                        model.all_tmp_uses[block_loc][tmp_atom].add((tmp_at_use, use_stmt_idx))
