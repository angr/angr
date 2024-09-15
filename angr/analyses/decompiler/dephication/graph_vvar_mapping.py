from __future__ import annotations
import logging
from collections import defaultdict

from ailment.block import Block
from ailment.expression import Phi, VirtualVariable
from ailment.statement import Assignment, Jump, ConditionalJump, Label

from angr.analyses import Analysis
from angr.analyses.s_reaching_definitions import SRDAModel
from angr.knowledge_plugins.functions import Function
from angr.analyses import register_analysis
from angr.utils.ssa import is_phi_assignment

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
        entry=None,
        vvar_id_start: int = 0,
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
        self._stmts_to_prepend = defaultdict(list)

        self.vvar_to_vvar_mapping = None
        self._rd: SRDAModel = self.project.analyses.SReachingDefinitions(
            subject=self._function, func_graph=self._graph
        ).model
        self._blocks: dict[tuple[int, int | None], Block] = {(block.addr, block.idx): block for block in self._graph}

        self._analyze()

    def _analyze(self):
        self.vvar_to_vvar_mapping = self._collect_and_remap()

    def _collect_and_remap(self) -> dict[int, int]:
        # collect phi assignments
        phi_to_srcvarid = self._collect_phi_assignments()

        # initialize phi_congruence_class
        phi_congruence_class: dict[int, set[int]] = {}
        for phi_varid in phi_to_srcvarid:
            phi_congruence_class[phi_varid] = {phi_varid}
        for src_and_varids in phi_to_srcvarid.values():
            for _, varid in src_and_varids:
                phi_congruence_class[varid] = {varid}

        # compute liveness
        liveness = self.project.analyses.SLiveness(self._function, func_graph=self._graph, entry=self._entry)

        live_ins = liveness.model.live_ins
        live_outs = liveness.model.live_outs
        interference = liveness.interference_graph()

        unresolved_neighbor_map = defaultdict(set)

        # check for interferences
        for phi_id, src_and_varids in phi_to_srcvarid.items():
            candidate_vvar_set: set[int] = set()
            src_and_varids = list(src_and_varids)

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

                    if interference.has_edge(var1, var2):
                        intersection_1 = phi_congruence_class[var1].intersection(live_outs[src1])
                        intersection_2 = phi_congruence_class[var2].intersection(live_outs[src2])
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
                varid, neighbors = max(unresolved_neighbor_map.items(), key=lambda x: len(x[1]))
                del unresolved_neighbor_map[varid]

                candidate_vvar_set.add(varid)

                for neighbor in neighbors:
                    if neighbor in unresolved_neighbor_map:
                        unresolved_neighbor_map[neighbor].discard(varid)
                        if not unresolved_neighbor_map[neighbor]:
                            del unresolved_neighbor_map[neighbor]

            # insert copies of variables as needed
            for varid in candidate_vvar_set:
                insertion_type, new_vvar_ids = self._insert_vvar_copy(varid, phi_id)

                if insertion_type == 0:
                    for src, old_vvar_id, new_vvar_id in new_vvar_ids:
                        phi_congruence_class[new_vvar_id] = {new_vvar_id}
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
                            interference.add_edge(new_vvar_id, vvar_id)

                else:  # insertion_type == 1
                    phi_block_loc, old_phi_varid, new_phi_varid = next(iter(new_vvar_ids))

                    phi_congruence_class[new_phi_varid] = {new_phi_varid}

                    live_ins[phi_block_loc].discard(old_phi_varid)
                    live_ins[phi_block_loc].add(new_phi_varid)

                    # update interference graph
                    for vvar_id in live_ins[phi_block_loc]:
                        interference.add_edge(new_phi_varid, vvar_id)

            # update phi_congruence_class
            (phidef_block_addr, phidef_block_idx), phidef_stmt_idx = self._vvar_defloc[phi_id]
            phi_block = self._blocks[(phidef_block_addr, phidef_block_idx)]
            phi_stmt = phi_block.statements[phidef_stmt_idx]

            new_class = phi_congruence_class[phi_stmt.dst.varid]
            for _, vvar in phi_stmt.src.src_and_vvars:
                if vvar is not None:
                    new_class |= phi_congruence_class[vvar.varid]
                    phi_congruence_class[vvar.varid] = new_class

        # append statements that were recorded for prepending
        for block, stmts in self._stmts_to_prepend.items():
            for stmt in stmts:
                self._prepend_stmt(block, stmt)

        # remove congruence classes with only one element
        for phi_varid in list(phi_congruence_class):
            if len(phi_congruence_class[phi_varid]) == 1:
                del phi_congruence_class[phi_varid]

        mapping: dict[int, int] = {}
        for phi_varid, congruence_class in phi_congruence_class.items():
            for varid in congruence_class:
                mapping[varid] = phi_varid

        return mapping

    def _insert_vvar_copy(self, varid: int, phi_varid: int) -> tuple[int, set]:
        (phidef_block_addr, phidef_block_idx), phidef_stmt_idx = self._vvar_defloc[phi_varid]
        if varid != phi_varid:
            # it's one of the source vvars

            phi_block = self._blocks[(phidef_block_addr, phidef_block_idx)]
            phi_stmt = phi_block.statements[phidef_stmt_idx]

            new_vvar_ids = set()

            for src, vvar in list(phi_stmt.src.src_and_vvars):
                if vvar is None or vvar.varid != varid:
                    continue

                new_vvar_id = self.vvar_id_start
                self.vvar_id_start += 1

                vvar = self._rd.varid_to_vvar[varid]
                src_block_addr, src_block_idx = src

                the_block = self._blocks[(src_block_addr, src_block_idx)]
                ins_addr = the_block.addr + the_block.original_size - 1
                new_vvar = VirtualVariable(
                    None, new_vvar_id, vvar.bits, vvar.category, oident=vvar.oident, ins_addr=ins_addr
                )
                assignment = Assignment(None, new_vvar, vvar, ins_addr=ins_addr)

                self._append_stmt(the_block, assignment)

                # update the phi statement
                replaced_vvars: set[int] = set()
                for _, phi_used_vvar in list(phi_stmt.src.src_and_vvars):
                    if phi_used_vvar is not None and phi_used_vvar.varid == varid and varid not in replaced_vvars:
                        replaced, phi_stmt = phi_stmt.replace(phi_used_vvar, new_vvar)
                        assert replaced
                        replaced_vvars.add(varid)
                phi_block.statements[phidef_stmt_idx] = phi_stmt

                new_vvar_ids.add((src, varid, new_vvar_id))

            return 0, new_vvar_ids

        # it's the phi assignment destination vvar

        new_vvar_id = self.vvar_id_start
        self.vvar_id_start += 1

        phi_vvar = self._rd.varid_to_vvar[phi_varid]
        phi_block_addr, phi_block_idx = self._vvar_defloc[phi_varid][0]
        the_block = self._blocks[(phi_block_addr, phi_block_idx)]
        ins_addr = the_block.addr
        new_vvar = VirtualVariable(
            None, new_vvar_id, phi_vvar.bits, phi_vvar.category, oident=phi_vvar.oident, ins_addr=ins_addr
        )
        assignment = Assignment(None, phi_vvar, new_vvar, ins_addr=ins_addr)

        phi_stmt = the_block.statements[phidef_stmt_idx]
        replaced, phi_stmt = phi_stmt.replace(phi_vvar, new_vvar)
        the_block.statements[phidef_stmt_idx] = phi_stmt

        self._record_stmt_for_prepending(the_block, assignment)

        return 1, {((phi_block_addr, phi_block_idx), phi_varid, new_vvar_id)}

    @staticmethod
    def _append_stmt(block, stmt):
        if block.statements and isinstance(block.statements[-1], (Jump, ConditionalJump)):
            block.statements.insert(len(block.statements) - 1, stmt)
        else:
            block.statements.append(stmt)

    def _record_stmt_for_prepending(self, block, stmt):
        self._stmts_to_prepend[block].append(stmt)

    @staticmethod
    def _prepend_stmt(block, stmt):
        # TODO: This insertion breaks the assumption that all phi statements appear before any assignments. We must
        # TODO: fix the assumption elsewhere in the code base.
        first_nonlabel_idx = len(block.statements)
        for i, s in enumerate(block.statements):
            if not isinstance(s, Label):
                first_nonlabel_idx = i
                break
        block.statements.insert(first_nonlabel_idx, stmt)

    @staticmethod
    def _used_in_phi(dst_block, src_block, vvar_id: int) -> bool:
        src = src_block.addr, src_block.idx
        for stmt in dst_block.statements:
            if isinstance(stmt, Label):
                continue
            r, _ = is_phi_assignment(stmt)
            if r:
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
