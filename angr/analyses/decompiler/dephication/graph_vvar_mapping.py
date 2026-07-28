from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from angr.ailment import AILBlockRewriter
from angr.ailment.block import Block
from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.s_reaching_definitions import SRDAModel, SReachingDefinitions
from angr.knowledge_plugins.functions import Function
from angr.utils.ssa import is_phi_assignment

if TYPE_CHECKING:
    from angr.ailment import Manager

l = logging.getLogger(name=__name__)


class GraphDephicationVVarMapping(Analysis):  # pylint:disable=abstract-method
    """
    GraphDephicationVVarMapping collects information from an AIL graph regarding how virtual variables should be mapped
    to each other in order to remove phi variables. This mapping will later be used to transform a partial-SSA form of
    AIL graph to a conventional AIL graph.

    This class largely implements "Translating Out of Static Single Assignment Form" by Sreedhar et al.
    """

    def __init__(
        self,
        func: Function | str,
        ail_graph,
        ail_manager: Manager,
        entry=None,
        vvar_id_start: int = 0,
        arg_vvars: list[VirtualVariable] | None = None,
    ):
        """
        :param func:                            The subject of the analysis: a function, or a single basic block
        :param ail_graph:                       The AIL graph to transform.
        """

        if isinstance(func, str):
            self._function = self.kb.functions[func]
        else:
            self._function = func
        self._graph = ail_graph
        self._entry = (
            entry
            if entry is not None
            else next(iter(bb for bb in self._graph if bb.addr == self._function.addr and bb.idx is None))
        )
        self._vvar_defloc = {}
        self.vvar_id_start = vvar_id_start
        self.ail_manager = ail_manager
        self._stmts_to_prepend = defaultdict(list)
        self._arg_vvars = arg_vvars or []

        self.vvar_to_vvar_mapping = None
        self.copied_vvar_ids: set[int] = set()
        self._rd: SRDAModel = SReachingDefinitions(self.project, subject=self._function, func_graph=self._graph).model
        self._blocks: dict[tuple[int, int | None], Block] = {(block.addr, block.idx): block for block in self._graph}

        self._analyze()

    def _analyze(self):
        self.vvar_to_vvar_mapping = self._collect_and_remap()

    def _collect_and_remap(self) -> dict[int, int]:
        # collect phi assignments
        phi_to_srcvarid = self._collect_phi_assignments()

        # compute liveness
        liveness = self.project.analyses.SLiveness(
            self._function, func_graph=self._graph, entry=self._entry, arg_vvars=self._arg_vvars
        )

        live_ins = liveness.model.live_ins
        live_outs = liveness.model.live_outs
        interference = liveness.interference_graph()

        # Phi congruence classes, maintained incrementally in a union-find structure. Each class keeps the set of its
        # members and the set of vvars interfering with *any* of its members, which lets us test interference between
        # two whole classes instead of between two individual vvars. This matters because a congruence class is the
        # transitive closure over phi statements: two vvars that never appear together in a single phi statement can
        # still land in the same class through a chain of phi statements, and if they interfere the class is not
        # conventional-SSA -- the naive coalescing performed later when the SSA form is destroyed would then merge two
        # simultaneously live values into one variable.
        parent: dict[int, int] = {}
        members: dict[int, set[int]] = {}
        interferes_with: dict[int, set[int]] = {}

        def _make(v: int) -> None:
            if v not in parent:
                parent[v] = v
                members[v] = {v}
                nbrs = set(interference[v]) if interference.has_node(v) else set()
                nbrs.discard(v)  # a self-loop carries no information for coalescing
                interferes_with[v] = nbrs

        def _find(v: int) -> int:
            _make(v)
            root = v
            while parent[root] != root:
                root = parent[root]
            while parent[v] != root:
                parent[v], v = root, parent[v]
            return root

        def _classes_interfere(v0: int, v1: int) -> bool:
            r0, r1 = _find(v0), _find(v1)
            if r0 == r1:
                return False
            if len(members[r0]) > len(members[r1]):
                r0, r1 = r1, r0
            return not interferes_with[r1].isdisjoint(members[r0])

        def _union(v0: int, v1: int) -> None:
            r0, r1 = _find(v0), _find(v1)
            if r0 == r1:
                return
            if len(members[r0]) < len(members[r1]):
                r0, r1 = r1, r0
            parent[r1] = r0
            members[r0] |= members[r1]
            interferes_with[r0] |= interferes_with[r1]
            del members[r1]
            del interferes_with[r1]

        def _note_interference(v0: int, v1: int) -> None:
            if v0 == v1:
                return
            interference.add_edge(v0, v1)
            interferes_with[_find(v0)].add(v1)
            interferes_with[_find(v1)].add(v0)

        def _loc_key(loc: tuple[int, int | None]) -> tuple[int, int]:
            return loc[0], -1 if loc[1] is None else loc[1]

        # process phi statements in a deterministic order
        phi_ids = sorted(
            phi_to_srcvarid,
            key=lambda vid: (_loc_key(self._vvar_defloc[vid][0]), self._vvar_defloc[vid][1], vid),
        )

        for phi_id in phi_ids:
            src_and_varids = sorted(phi_to_srcvarid[phi_id], key=lambda t: (_loc_key(t[0]), t[1]))
            candidate_vvar_set: set[int] = set()
            unresolved_neighbor_map: defaultdict[int, set[int]] = defaultdict(set)

            for i in range(-1, len(src_and_varids)):
                for j in range(i + 1, len(src_and_varids)):
                    if i == -1:
                        src1 = self._vvar_defloc[phi_id][0]
                        var1 = phi_id
                    else:
                        src1, var1 = src_and_varids[i]
                    src2, var2 = src_and_varids[j]

                    if var1 == var2:
                        continue

                    if _classes_interfere(var1, var2):
                        # the intersection considers both liveouts and the vvars used in the last statement of the
                        # block if it is a jump or a conditional jump because we cannot insert a vvar copy statement
                        # after the jump. this is a special case that is not covered in Sreedhar et al.'s paper. It is
                        # documented in "Revisiting Out-of-SSA Translation for Correctness, Code Quality, and
                        # Efficiency" (Section II.A) by Boissinot et. al.
                        intersection_1 = members[_find(var1)].intersection(
                            live_outs[src2] | liveness.model.block_end_vvars.get(src2, set())
                        )
                        intersection_2 = members[_find(var2)].intersection(
                            live_outs[src1] | liveness.model.block_end_vvars.get(src1, set())
                        )
                        if intersection_1 and not intersection_2:
                            # case 1
                            candidate_vvar_set.add(var1)
                        elif not intersection_1 and intersection_2:
                            # case 2
                            candidate_vvar_set.add(var2)
                        elif intersection_1 and intersection_2:
                            # case 3
                            candidate_vvar_set.add(var1)
                            candidate_vvar_set.add(var2)
                        else:
                            # case 4
                            unresolved_neighbor_map[var1].add(var2)
                            unresolved_neighbor_map[var2].add(var1)

            # process unresolved_neighbor_map in a decreasing order of the number of neighbors
            while unresolved_neighbor_map:
                varid, neighbors = max(unresolved_neighbor_map.items(), key=lambda x: (len(x[1]), x[0]))
                del unresolved_neighbor_map[varid]

                candidate_vvar_set.add(varid)

                for neighbor in neighbors:
                    if neighbor in unresolved_neighbor_map:
                        unresolved_neighbor_map[neighbor].discard(varid)
                        if not unresolved_neighbor_map[neighbor]:
                            del unresolved_neighbor_map[neighbor]

            # insert copies of variables as needed
            for varid in sorted(candidate_vvar_set):
                insertion_type, new_vvar_ids = self._insert_vvar_copy(varid, {phi_id})

                if insertion_type == 0:
                    for src, old_vvar_id, new_vvar_id in sorted(
                        new_vvar_ids, key=lambda t: (_loc_key(t[0]), t[1], t[2])
                    ):
                        self.copied_vvar_ids.add(new_vvar_id)
                        _make(new_vvar_id)
                        live_outs[src].add(new_vvar_id)

                        src_block = self._blocks[(src[0], src[1])]
                        for succ in self._graph.successors(src_block):
                            succ_key = succ.addr, succ.idx
                            if old_vvar_id not in live_ins[succ_key] and not self._used_in_phi(
                                succ, src_block, old_vvar_id
                            ):
                                live_outs[src].discard(old_vvar_id)

                        # update interference graph
                        for vvar_id in live_outs[src]:
                            _note_interference(new_vvar_id, vvar_id)

                else:  # insertion_type == 1, i.e. the copy replaces the phi destination
                    for phi_block_loc, old_phi_varid, new_phi_varid in sorted(
                        new_vvar_ids, key=lambda t: (_loc_key(t[0]), t[1], t[2])
                    ):
                        self.copied_vvar_ids.add(new_phi_varid)
                        _make(new_phi_varid)

                        live_ins[phi_block_loc].discard(old_phi_varid)
                        live_ins[phi_block_loc].add(new_phi_varid)

                        # update interference graph
                        for vvar_id in live_ins[phi_block_loc]:
                            _note_interference(new_phi_varid, vvar_id)

            # merge the congruence classes of the phi destination and its (possibly rewritten) sources
            (phidef_block_addr, phidef_block_idx), phidef_stmt_idx = self._vvar_defloc[phi_id]
            phi_block = self._blocks[(phidef_block_addr, phidef_block_idx)]
            # phi_stmt is the newly created phi statement with variables replaced
            phi_stmt = phi_block.statements[phidef_stmt_idx]
            for _, src_vvar in phi_stmt.src.src_and_vvars:
                if src_vvar is not None:
                    _union(phi_stmt.dst.varid, src_vvar.varid)

        # append statements that were recorded for prepending
        for block, stmts in self._stmts_to_prepend.items():
            for stmt in stmts:
                self._prepend_stmt(block, stmt)

        mapping: dict[int, int] = {}
        for class_members in members.values():
            if len(class_members) <= 1:
                # congruence classes with only one element require no remapping
                continue
            rep = min(class_members)
            for varid in class_members:
                mapping[varid] = rep

        return mapping

    def _insert_vvar_copy(
        self, varid: int, phi_varids: set[int]
    ) -> tuple[int, set[tuple[tuple[int, int | None], int, int]]]:
        new_vvar_info: set[tuple[tuple[int, int | None], int, int]] = set()
        new_vvar_id = self.vvar_id_start
        self.vvar_id_start += 1

        if varid not in phi_varids:
            # it's one of the source vvars

            stmt_appended_locs: dict[tuple[int, int | None], VirtualVariable] = {}

            # update all phi statements
            for phi_varid in phi_varids:
                (phidef_block_addr, phidef_block_idx), phidef_stmt_idx = self._vvar_defloc[phi_varid]
                phi_block = self._blocks[(phidef_block_addr, phidef_block_idx)]
                phi_stmt = phi_block.statements[phidef_stmt_idx]

                for src, vvar in list(phi_stmt.src.src_and_vvars):
                    if vvar is None or vvar.varid != varid:
                        continue

                    assignment_created = False
                    if src not in stmt_appended_locs:
                        # we have not yet appended a statement to this block
                        the_block = self._blocks[src]
                        ins_addr = (
                            the_block.addr + (the_block.original_size if the_block.original_size is not None else 1) - 1
                        )
                        new_category = phi_stmt.dst.category
                        new_oident = phi_stmt.dst.oident
                        new_vvar = VirtualVariable(
                            self.ail_manager.next_atom(),
                            new_vvar_id,
                            vvar.bits,
                            new_category,
                            oident=new_oident,
                            ins_addr=ins_addr,
                        )
                        assignment = Assignment(
                            self.ail_manager.next_atom(), new_vvar, vvar, ins_addr=ins_addr, dephi=True
                        )
                        self._append_stmt(the_block, assignment, old_vvarid=varid, new_vvarid=new_vvar_id)

                        stmt_appended_locs[src] = new_vvar
                        assignment_created = True

                    else:
                        new_vvar = stmt_appended_locs[src]

                    replaced_vvars: set[int] = set()
                    for _, phi_used_vvar in list(phi_stmt.src.src_and_vvars):
                        if phi_used_vvar is not None and phi_used_vvar.varid == varid and varid not in replaced_vvars:
                            replaced, phi_stmt = phi_stmt.replace(phi_used_vvar, new_vvar)
                            assert replaced
                            replaced_vvars.add(varid)
                    phi_block.statements[phidef_stmt_idx] = phi_stmt

                    new_vvar_info.add((src, varid, new_vvar_id))

                    if assignment_created:
                        # tick new_vvar_id and self.vvar_id_start
                        new_vvar_id += 1
                        self.vvar_id_start += 1

            return 0, new_vvar_info

        # it's the phi assignment destination vvar

        for phi_varid in phi_varids:
            phi_vvar = self._rd.varid_to_vvar[phi_varid]
            (phidef_block_addr, phidef_block_idx), phidef_stmt_idx = self._vvar_defloc[phi_varid]
            the_block = self._blocks[(phidef_block_addr, phidef_block_idx)]
            ins_addr = the_block.addr
            new_vvar = VirtualVariable(
                self.ail_manager.next_atom(),
                new_vvar_id,
                phi_vvar.bits,
                phi_vvar.category,
                oident=phi_vvar.oident,
                ins_addr=ins_addr,
            )
            assignment = Assignment(self.ail_manager.next_atom(), phi_vvar, new_vvar, ins_addr=ins_addr, dephi=True)

            phi_stmt = the_block.statements[phidef_stmt_idx]
            replaced, phi_stmt = phi_stmt.replace(phi_vvar, new_vvar)
            the_block.statements[phidef_stmt_idx] = phi_stmt

            self._record_stmt_for_prepending(the_block, assignment)

            new_vvar_info.add(((phidef_block_addr, phidef_block_idx), phi_varid, new_vvar_id))

        return 1, new_vvar_info

    def _append_stmt(self, block, stmt, old_vvarid: int | None = None, new_vvarid: int | None = None):
        def _handle_VirtualVariable(  # pylint:disable=unused-argument
            expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt, block: Block | None
        ):
            assert old_vvarid is not None and new_vvarid is not None
            return (
                expr
                if expr.varid != old_vvarid
                else VirtualVariable(
                    self.ail_manager.next_atom(), new_vvarid, expr.bits, expr.category, oident=expr.oident, **expr.tags
                )
            )

        if block.statements and isinstance(block.statements[-1], (Jump, ConditionalJump)):
            block.statements.insert(len(block.statements) - 1, stmt)

            # replace the vvar usage in the last statement if it's used there
            if old_vvarid is not None and new_vvarid is not None:
                replacer = AILBlockRewriter()
                replacer.expr_handlers[VirtualVariable] = _handle_VirtualVariable
                new_stmt = replacer.walk_statement(block.statements[-1])
                if new_stmt is not None and new_stmt is not block.statements[-1]:
                    block.statements[-1] = new_stmt

        else:
            block.statements.append(stmt)

    def _record_stmt_for_prepending(self, block, stmt):
        self._stmts_to_prepend[block].append(stmt)

    @staticmethod
    def _prepend_stmt(block, stmt):
        first_nonlabel_nonphi_idx = len(block.statements)
        for i, s in enumerate(block.statements):
            if not isinstance(s, Label) and not is_phi_assignment(s):
                first_nonlabel_nonphi_idx = i
                break
        block.statements.insert(first_nonlabel_nonphi_idx, stmt)

    @staticmethod
    def _used_in_phi(dst_block, src_block, vvar_id: int) -> bool:
        src = src_block.addr, src_block.idx
        for stmt in dst_block.statements:
            if isinstance(stmt, Label):
                continue
            if is_phi_assignment(stmt):
                for src_, vvar in stmt.src.src_and_vvars:
                    if src_ == src and vvar is not None and vvar.varid == vvar_id:
                        return True
            else:
                # early exit
                return False
        return False

    def _collect_phi_assignments(self) -> dict[int, set[tuple[tuple[int, int], int]]]:
        g = self._graph
        phi_to_src = defaultdict(set)

        for block in g:
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    if isinstance(stmt.src, Phi):
                        for src, vvar in stmt.src.src_and_vvars:
                            if vvar is None:
                                l.debug("Invalid vvar None found in %r.src.src_and_vvars.", stmt)
                            else:
                                phi_to_src[stmt.dst.varid].add((src, vvar.varid))
                    self._vvar_defloc[stmt.dst.varid] = (block.addr, block.idx), stmt_idx

        return phi_to_src


register_analysis(GraphDephicationVVarMapping, "GraphDephicationVVarMapping")
