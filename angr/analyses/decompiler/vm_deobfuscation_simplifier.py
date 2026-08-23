from __future__ import annotations

import logging
import os
from collections import defaultdict

import networkx

from angr import ailment
from angr.ailment import Expr, Stmt
from angr.ailment.block_walker import AILBlockWalker
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.knowledge_plugins.key_definitions import atoms
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE

from .ailgraph_walker import AILGraphWalker, RemoveNodeNotice
from .block_simplifier import BlockSimplifier
from .peephole_optimizations.base import PeepholeOptimizationExprBase

l = logging.getLogger(name=__name__)


class ThemidaCondSimplify2(PeepholeOptimizationExprBase):
    """
    Drop the mask a Themida flag check ors/ands onto amd64g_calculate_rflags_all when the mask
    leaves the zero bit alone.
    """

    __slots__ = ()

    NAME = "Themida flag check simplifications"
    expr_classes = (ailment.expression.BinaryOp,)

    def optimize(self, expr, **kwargs):
        if not (
            isinstance(expr.operands[0], ailment.expression.DirtyExpression)
            and expr.operands[0].dirty_expr.cee_name == "amd64g_calculate_rflags_all"
        ):
            return None
        if expr.op == "Or" and isinstance(expr.operands[1], ailment.expression.Const):
            if (expr.operands[1].value & 0x40) >> 6 == 0:
                return expr.operands[0]
        elif (
            expr.op == "Or"
            and isinstance(expr.operands[1], ailment.expression.BinaryOp)
            and expr.operands[1].op == "And"
            and isinstance(expr.operands[1].operands[1], ailment.expression.Const)
        ):
            if (expr.operands[1].operands[1].value & 0x40) >> 6 == 0:
                return expr.operands[0]
        elif expr.op == "And" and isinstance(expr.operands[1], ailment.expression.Const):
            if (expr.operands[1].value & 0x40) >> 6 == 1:
                return expr.operands[0]
        return None


class _StackReferenceUndoer(ailment.AILBlockRewriter):
    """
    Rewrite ``Reference(vvar{stack N}) ± k`` into the plain stack address it denotes, so that the
    next stack-variable SSA pass can turn that slot into a virtual variable of its own.

    Only offsets that land **outside** the referenced variable are rewritten. An offset inside it
    names storage that already lives in the virtual variable rather than in memory; converting it
    would give the same bytes two independent SSA names, and every value written through one and
    read through the other would be lost.
    """

    def __init__(self, ail_manager, arch_bits):
        super().__init__(update_block=True)
        self._ail_manager = ail_manager
        self._arch_bits = arch_bits

    @classmethod
    def _resolve(cls, expr):
        """
        ``(vvar, absolute stack offset)`` for a chain of constant adds and subtracts over the
        address of a stack variable, or None. The VM builds its addresses one ``+8`` at a time, so
        the chain can be several deep.
        """
        if (
            isinstance(expr, Expr.UnaryOp)
            and expr.op == "Reference"
            and isinstance(expr.operand, Expr.VirtualVariable)
            and expr.operand.was_stack
            and expr.operand.stack_offset is not None
        ):
            return expr.operand, expr.operand.stack_offset
        if isinstance(expr, Expr.BinaryOp) and expr.op in ("Add", "Sub"):
            base, offset = expr.operands
            if expr.op == "Add" and isinstance(base, Expr.Const):
                base, offset = offset, base
            if isinstance(offset, Expr.Const):
                resolved = cls._resolve(base)
                if resolved is not None:
                    vvar, value = resolved
                    return vvar, (value + offset.value if expr.op == "Add" else value - offset.value)
        return None

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        resolved = self._resolve(expr)
        if resolved is not None:
            vvar, value = resolved
            if value > (1 << (self._arch_bits - 1)) - 1:
                value -= 1 << self._arch_bits
            if not vvar.stack_offset <= value < vvar.stack_offset + vvar.size:
                return Expr.StackBaseOffset(self._ail_manager.next_atom(), expr.bits, value, **expr.tags)
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)


class VMDeobfuscationSimplifierMixin:
    """
    The AIL graph transforms pushan runs on a devirtualized function, lifted out of its Clinic._analyze
    into a mixin so that they can be attached to angr's stage-based Clinic.

    Every one of them takes the AIL graph and returns it (some mutate in place). They only reach for
    ``self.project``, ``self.kb`` and ``self.function`` from the surrounding Clinic.
    """

    #
    # Driver
    #

    #: How many un-reference / stack-SSA / simplify rounds to run after the transforms. Each one
    #: resolves a further level of indirection through a VM's emulated operand stack.
    VM_DEOBF_SSA_ROUNDS = 6

    #: (transform name, whether to re-simplify the function afterwards), in pushan's order
    VM_DEOBF_TRANSFORMS = (
        ("_remove_cyclic_def_use", True),
        ("remove_same_branches", True),
        ("calculate_flags_simplifier", True),
        ("_remove_cyclic_def_use", True),
        ("remove_all_empty_nodes", True),
        ("consecutive_store_load_across_blocks", True),
        ("separate_overlapping_blocks", True),
        ("move_common_suffix_to_next_node", True),
        ("conseq_xor_simplification", True),
        ("_remove_cyclic_def_use", True),
        ("remove_redundant_conditional_check", True),
        ("remove_all_empty_nodes", True),
        ("remove_redundant_conditional_check", False),
    )

    def _run_vm_deobfuscation_simplifications(self, ail_graph):
        """
        Run pushan's devirtualization clean-ups, re-simplifying the function between them the way
        its own Clinic._analyze did.
        """
        for idx, (name, resimplify) in enumerate(self.VM_DEOBF_TRANSFORMS):
            transform = getattr(self, name)
            try:
                returned = transform(ail_graph)
            except Exception:  # pylint:disable=broad-except
                l.warning("VM-deobfuscation transform %s failed; skipping it", name, exc_info=True)
                continue
            if returned is not None:
                ail_graph = returned
            if resimplify:
                ail_graph = self._vm_deobf_resimplify(ail_graph)
            self._dump_vm_transform(idx, name, ail_graph)
        return ail_graph

    def _vm_seed_initial_values(self, ail_graph):
        """
        Materialize ``ail_propagator_init_values`` as statements at the top of the entry block.

        The deobfuscator starts in the middle of a function, so pointers its caller set up -- for
        Tigress, the addresses of the VM's input and output buffers -- are read before anything in
        the recovered graph writes them. pushan seeded them into its AIL propagator's initial
        state; on the SSA pipeline the same information is an assignment at the entry.
        """
        init = self.ail_propagator_init_values
        if not init:
            return ail_graph
        entry = next((bb for bb in ail_graph if (bb.addr, bb.idx) == self.entry_node_addr), None)
        if entry is None:
            return ail_graph

        arch = self.project.arch
        ins_addr = next((stmt.tags.get("ins_addr") for stmt in entry.statements if stmt.tags.get("ins_addr")), entry.addr)

        def _fresh(expr):
            # the caller built these expressions; give them ids from our manager
            if isinstance(expr, Expr.StackBaseOffset):
                return Expr.StackBaseOffset(self._ail_manager.next_atom(), expr.bits, expr.offset)
            return expr

        seeded = []
        for stack_offset, propvalue in init.get("stack", []):
            value = propvalue.one_expr
            if value is None:
                continue
            addr = Expr.StackBaseOffset(self._ail_manager.next_atom(), arch.bits, stack_offset)
            seeded.append(
                Stmt.Store(
                    self._ail_manager.next_atom(),
                    addr,
                    _fresh(value),
                    value.bits // arch.byte_width,
                    arch.memory_endness,
                    ins_addr=ins_addr,
                )
            )
        for reg_offset, propvalue in init.get("reg", []):
            value = propvalue.one_expr
            if value is None or reg_offset in (arch.sp_offset, arch.bp_offset):
                # the stack pointer tracker already seeds sp and bp with the frame base
                continue
            dst = Expr.Register(self._ail_manager.next_atom(), None, reg_offset, value.bits)
            seeded.append(Stmt.Assignment(self._ail_manager.next_atom(), dst, _fresh(value), ins_addr=ins_addr))

        if not seeded:
            return ail_graph
        at = 1 if entry.statements and isinstance(entry.statements[0], Stmt.Label) else 0
        entry.statements = entry.statements[:at] + seeded + entry.statements[at:]
        l.info("Seeded %d initial value(s) at the devirtualized entry block", len(seeded))
        return ail_graph

    @staticmethod
    def _vm_graph_fingerprint(ail_graph):
        """
        Statements plus unresolved memory accesses. Each stack-SSA round turns loads and stores at
        addresses that just became static into virtual variables, so the second number falls even
        when the first does not.
        """
        stmts = 0
        memory_ops = 0
        for block in ail_graph.nodes():
            stmts += len(block.statements)
            text = block.dbg_repr()
            memory_ops += text.count("Load(") + text.count("STORE(")
        return stmts, memory_ops

    def _vm_unreference_stack_addrs(self, ail_graph):
        """
        Rewrite ``Reference(vvar{stack N})`` back into ``StackBaseOffset(N)``.

        Ssailification turns a stack address that escapes a Load/Store into a Reference and stops
        treating that region as stack variables. Once the VM's operand-stack pointer has been
        propagated, those references sit inside Load/Store addresses again, where a fresh
        stack-variable SSA pass can turn each slot into a virtual variable -- but only if the
        address is a StackBaseOffset once more.
        """
        rewriter = _StackReferenceUndoer(self._ail_manager, self.project.arch.bits)
        for block in list(ail_graph.nodes()):
            rewriter.walk(block)
        return ail_graph

    def _vm_drop_unreachable(self, ail_graph):
        """
        Rewiring blocks can orphan a region. Liveness only covers what the entry reaches, so an
        orphan makes dephication index its model with a key that is not there.
        """
        entry = next((bb for bb in ail_graph if (bb.addr, bb.idx) == self.entry_node_addr), None)
        if entry is None:
            return ail_graph
        reachable = networkx.descendants(ail_graph, entry) | {entry}
        unreachable = [bb for bb in ail_graph if bb not in reachable]
        if unreachable:
            l.debug("Dropping %d block(s) the devirtualized entry no longer reaches", len(unreachable))
            ail_graph.remove_nodes_from(unreachable)
        return ail_graph

    def _vm_repair_phis(self, ail_graph):
        """
        The transforms remove and rewire blocks, which leaves phi statements naming source blocks
        that are no longer predecessors. Dephication indexes its liveness model by those keys and
        raises, so drop the stale entries; a phi that keeps a single source becomes a plain copy.
        """
        new_blocks = {}
        for block in ail_graph.nodes():
            preds = {(p.addr, p.idx) for p in ail_graph.predecessors(block)}
            new_statements = None
            for idx, stmt in enumerate(block.statements):
                if not (isinstance(stmt, Stmt.Assignment) and isinstance(stmt.src, Expr.Phi)):
                    continue
                kept = [(src, vvar) for src, vvar in stmt.src.src_and_vvars if src in preds]
                if len(kept) == len(stmt.src.src_and_vvars):
                    continue
                if not kept:
                    # nothing survived: keep one entry per current predecessor so that the block
                    # keys at least exist, with no value flowing in along them
                    kept = [(src, None) for src in sorted(preds)]
                    if not kept:
                        continue
                if new_statements is None:
                    new_statements = list(block.statements)
                if len(kept) == 1 and kept[0][1] is not None:
                    new_src = kept[0][1]
                else:
                    new_src = Expr.Phi(stmt.src.idx, stmt.src.bits, kept, **stmt.src.tags)
                new_statements[idx] = Stmt.Assignment(stmt.idx, stmt.dst, new_src, **stmt.tags)
            if new_statements is not None:
                new_block = block.copy()
                new_block.statements = new_statements
                new_blocks[block] = new_block

        if new_blocks:
            AILGraphWalker(ail_graph, lambda node: new_blocks.get(node, None), replace_nodes=True).walk()
        return ail_graph

    def _dump_vm_transform(self, idx, name, ail_graph):
        directory = os.environ.get("CLINIC_STAGE_DUMP")
        if not directory:
            return
        with open(f"{directory}/vm_{idx:02d}_{name.lstrip('_')}.txt", "w") as fp:
            fp.write(f"nodes={ail_graph.number_of_nodes()} edges={ail_graph.number_of_edges()}\n")
            for block in sorted(ail_graph.nodes(), key=lambda b: (b.addr, b.idx or 0)):
                succs = ", ".join(f"{s.addr:x}" for s in ail_graph.successors(block))
                fp.write(f"-> [{succs}]\n{block.dbg_repr()}\n")

    def _vm_deobf_resimplify(self, ail_graph):
        """
        pushan's ``_simplify_function`` + ``_simplify_blocks`` pair, expressed with the arguments
        modern Clinic's post-SSA simplification uses.
        """
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stackarg_offset_manager=self._stackarg_offset_manager,
            unify_variables=True,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            removed_vvar_ids=self._removed_vvar_ids,
            arg_vvars=self.arg_vvars,
            preserve_vvar_ids=self._preserve_vvar_ids,
        )
        return self._simplify_blocks(
            ail_graph,
            stack_pointer_tracker=self._spt,
            preserve_vvar_ids=self._preserve_vvar_ids,
            type_hints=self._type_hints,
        )

    def tmp_peephole_optimizations(self, ail_graph):
        # tmp_426 = 32 - tmp_267;
        # tmp_586 = tmp_426 + tmp_267;
        new_blocks = {}

        for node in ail_graph.nodes():
            prev_stmt = None
            new_stmts=[]
            for stmt in node.statements:
                new_stmt=stmt
                if isinstance(stmt, Stmt.Assignment) and isinstance(stmt.dst, Expr.Tmp) and \
                        isinstance(prev_stmt, Stmt.Assignment) and isinstance(prev_stmt.dst, Expr.Tmp) and \
                        isinstance(stmt.src, Expr.BinaryOp) and stmt.src.op == "Add" and \
                        prev_stmt.dst.likes(stmt.src.operands[0]):

                    if isinstance(prev_stmt.src, Expr.BinaryOp) and prev_stmt.src.op == "Sub" and \
                        isinstance(prev_stmt.src.operands[0], Expr.Const) and \
                        prev_stmt.src.operands[1].likes(stmt.src.operands[1]):
                        new_stmt = Stmt.Assignment(src=prev_stmt.src.operands[0], dst=stmt.dst, idx=stmt.idx, **stmt.tags)
                        import ipdb;ipdb.set_trace()

                elif isinstance(stmt, Stmt.Assignment) and isinstance(stmt.dst, Expr.Tmp) and \
                        isinstance(prev_stmt, Stmt.Assignment) and isinstance(prev_stmt.dst, Expr.Tmp) and \
                        isinstance(stmt.src, Expr.BinaryOp) and stmt.src.op == "Sub" and \
                        prev_stmt.dst.likes(stmt.src.operands[0]):

                    if isinstance(prev_stmt.src, Expr.BinaryOp) and prev_stmt.src.op == "Add" and \
                        isinstance(prev_stmt.src.operands[0], Expr.Const) and \
                        prev_stmt.src.operands[1].likes(stmt.src.operands[1]):
                        new_stmt = Stmt.Assignment(src=prev_stmt.src.operands[0], dst=stmt.dst, idx=stmt.idx, **stmt.tags)
                        import ipdb;ipdb.set_trace()

                new_stmts.append(new_stmt)
                if new_stmt != stmt:
                    #skip the modified stmts
                    prev_stmt=None
                else:
                    prev_stmt=stmt

            if new_stmts != node.statements:
                new_block = node.copy()
                new_block.statements = new_stmts
                new_blocks[node] = new_block
        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph



    def and_multiple_conditions(self, ail_graph):

        def find_if_else_triangle(node):
            # find this shape in the graph
            #                       node_a
            #                      /    \
            #                node_b      \
            #                     \      /
            #                      node_c

            succs = list(ail_graph.successors(node))
            merge_point_node = None
            body_node= None
            if len(succs) == 2:
                for succ in succs:
                    preds_of_succ = list(ail_graph.predecessors(succ))
                    if len(preds_of_succ) == 2:
                        for pred in preds_of_succ:
                            if pred in succs:
                                merge_point_node = succ

                if merge_point_node:
                    for succ in succs:
                        if succ != merge_point_node:
                            body_node = succ

            return merge_point_node, body_node

        def same_statements(node_a, node_b):
            new_stmts_a=[]
            new_stmts_b=[]

            #remove the label and jmp before comparing
            for stmt in node_a.statements:
                if not isinstance(stmt, Stmt.Label) and not isinstance(stmt, Stmt.Jump):
                    new_stmts_a.append(stmt)
            for stmt in node_b.statements:
                if not isinstance(stmt, Stmt.Label) and not isinstance(stmt, Stmt.Jump):
                    new_stmts_b.append(stmt)
            if len(new_stmts_a) != len(new_stmts_b):
                return False
            else:
                for i in range(len(new_stmts_a)):
                    if not new_stmts_b[i].likes(new_stmts_a[i]):
                        return False
            return True


        new_blocks = {}
        nodes_to_remove = set()
        edges_to_add = set()
        # merge multiple if else into one by oring the all the conditions in order
        # the body for all the if else is same
        for node in ail_graph.nodes():
            if node in nodes_to_remove:
                continue
            merge_point_a, body_a = find_if_else_triangle(node)
            if merge_point_a in nodes_to_remove:
                continue

            if merge_point_a and len(merge_point_a.statements) == 2:
                merge_point_b, body_b = find_if_else_triangle(merge_point_a)
                if merge_point_b in nodes_to_remove:
                    continue
                if merge_point_b and same_statements(body_a, body_b) and len(merge_point_b.statements) == 2:
                    if node.statements[-1].true_target.value == merge_point_a.addr and \
                        merge_point_a.statements[-1].true_target.value == merge_point_b.addr:
                        new_node = node.copy()
                        new_condition = Expr.BinaryOp(None, "LogicalAnd",
                                                      (new_node.statements[-1].condition, merge_point_a.statements[-1].condition),
                                                      new_node.statements[-1].condition.signed)
                        new_cond_stmt = Stmt.ConditionalJump(None, condition=new_condition,
                                                             true_target=merge_point_a.statements[-1].true_target,
                                                             false_target=merge_point_a.statements[-1].false_target,
                                                             **merge_point_a.statements[-1].tags)
                        new_stmts = new_node.statements[:-1] + [new_cond_stmt]
                        new_node.statements = new_stmts
                        new_blocks[node] = new_node

                        nodes_to_remove.add(body_a)
                        nodes_to_remove.add(merge_point_a)
                        edges_to_add.add((node.addr, merge_point_b.addr))
                        edges_to_add.add((node.addr, body_b.addr))

        for node in nodes_to_remove:
            ail_graph.remove_node(node)

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()


        node_map = {}
        for node in ail_graph.nodes():
            node_map[node.addr] = node

        for n1_addr, n2_addr in edges_to_add:
            ail_graph.add_edge(node_map[n1_addr], node_map[n2_addr])

        return ail_graph
    def conseq_xor_simplification(self, ail_graph):
        # tmp_4075 = 82 ^ tmp_4071;                   ==>>              tmp_4075 = 82 ^ tmp_4071;
        # tmp_4080 = tmp_4075 ^ tmp_4071;                               tmp_4080 = 82;
        new_blocks = {}

        for node in ail_graph.nodes():
            new_stmts = []
            idx=0
            while idx < len(node.statements):
                stmt=node.statements[idx]
                if idx+1 < len(node.statements):
                    nex_stmt=node.statements[idx+1]
                    if isinstance(stmt, Stmt.Assignment) and isinstance(stmt.src, Expr.BinaryOp) and stmt.src.op == "Xor" and \
                        isinstance(nex_stmt, Stmt.Assignment) and isinstance(nex_stmt.src, Expr.BinaryOp) and \
                                nex_stmt.src.op == "Xor" and nex_stmt.src.operands[0].likes(stmt.dst) and \
                                nex_stmt.src.operands[1].likes(stmt.src.operands[1]):
                            new_stmt=Stmt.Assignment(src=stmt.src.operands[0], dst=nex_stmt.dst, idx=stmt.idx, **stmt.tags)
                            new_stmts.append(stmt)
                            new_stmts.append(new_stmt)
                            idx+=1
                    else:
                        new_stmts.append(stmt)
                else:
                    new_stmts.append(stmt)

                idx+=1

            if new_stmts != node.statements:
                new_block = node.copy()
                new_block.statements = new_stmts
                new_blocks[node] = new_block

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    def move_common_suffix_to_next_node(self, ail_graph):
        # if (tmp_1369)
        #     {
        #         v20 = v1;
        #     v56 = & v18;
        #     }
        #     else
        #     {
        #         v52 = (v1 >> 10 == 1 ? -1: 1);
        #     v53 = (v1 >> 21 == 1 ? 1: 0);
        #     v54 = (v1 >> 18 == 1 ? 1: 0);
        #     (unsigned int)
        #     v55 = K32EnumProcessModules(v29, & v35, 8, & v31);
        #     v5 = v55;
        #     v26 = ~((int)v5);
        #     v25 = ~((int)v5);
        #     v15 = [D]
        #     amd64g_calculate_rflags_all(0x13 < 64 >, Conv(32->64, ((BitwiseNeg
        #                                                             Load(addr=stack_base-4784, size=4, endness=Iend_LE)) & (
        #                                                               BitwiseNeg
        #                                                               Load(addr=stack_base-4780, size=4, endness=Iend_LE)))), 0x0 < 64 >, 0x0 < 64 >) | v52 & 0x400 | v53 * 0x200000 & 0x200000 | v54 * 0x40000 & 0x40000;
        #     v0 = ~(~(-1 + ((64 & ~(~(v15))) >> 6)) | -5368823256) + ~(~(~(-1 + ((64 & ~(~(v15))) >> 6))) | -5368823472);
        #     if (5369814829 + -(__ROL__(*(v0) ^ (int)v0, 1) - 1) - 919160423 != sub_1400d5150)
        #     {
        #     v20 = v15;
        #     v56 = & v18;
        #     }
        #     else
        #     {
        #     v21 = v15;
        #     v57 = * ((long long * ) & v35);
        #     v7 =[D] amd64g_calculate_rflags_all(0x0 < 64 >, cc_dep1 < 8 >, 0x0 < 64 >, 0x1 < 64 > ) | (v21 >> 10 == 1 ? -1: 1) & 0x400 | (
        #                 v21 >> 21 == 1 ? 1: 0) * 0x200000 & 0x200000 | (v21 >> 18 == 1 ? 1: 0) * 0x40000 & 0x40000;
        #     v3 = K32GetModuleBaseNameA(v29, v57, & v37, 260);
        #     v20 = v7;
        #     v56 = & v18;
        #     }
        #     }
        # move v56=&18 to the common successor
        new_blocks = {}

        for node in ail_graph.nodes():
            if len(list(ail_graph.predecessors(node))) > 1:
                preds = list(ail_graph.predecessors(node))
                common_stmts = preds[0].statements[:]

                for pred in preds[1:]:
                    tmp_comon_stmts = []
                    iter_ind = -1
                    while abs(iter_ind) <= min(len(common_stmts), len(pred.statements)):
                        if common_stmts[iter_ind].likes(pred.statements[iter_ind]) and not isinstance(common_stmts[iter_ind], Expr.Call):
                            tmp_comon_stmts.append(common_stmts[iter_ind])
                        else:
                            common_stmts = list(reversed(tmp_comon_stmts[:]))
                            break
                        iter_ind=iter_ind-1
                    if len(common_stmts) == 0:
                        #break early if already no matches
                        break

                if len(common_stmts) != 0:
                    keep_jmp_stmt=False
                    if isinstance(common_stmts[-1], Stmt.Jump):
                        keep_jmp_stmt=True

                    #remove these stmts from the parents
                    for pred in preds:
                        new_stmts = pred.statements[:-len(common_stmts)]
                        if keep_jmp_stmt:
                            new_stmts.append(common_stmts[-1])
                        new_block = pred.copy()
                        new_block.statements = new_stmts
                        new_blocks[pred] = new_block

                    new_stmts=[]
                    if isinstance(node.statements[0], Stmt.Label):
                        new_stmts.append(node.statements[0])

                    #add the statement to the common successor
                    if keep_jmp_stmt:
                        #remove jmp stmt when putting to next node
                        new_stmts = new_stmts + common_stmts[:-1]
                    else:
                        new_stmts = new_stmts + common_stmts

                    if isinstance(node.statements[0], Stmt.Label):
                        new_stmts = new_stmts + node.statements[1:]
                    else:
                        new_stmts = new_stmts + node.statements[:]

                    new_block = node.copy()
                    new_block.statements = new_stmts
                    new_blocks[node] = new_block

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    def calculate_flags_simplifier(self, ail_graph):
        # this siplifies if (!(((char)[D] x86g_calculate_eflags_all(0xf<32>, Load(addr=0x4260bc0<32>, size=4, endness=Iend_LE), 0x0<32>, 0x0<32>) | 2 | (char)v31 & 0 | (char)(v32 << 21) & 0 | (char)(v33 << 18) & 0) & 64))
        # to this        if (!(((char)[D] x86g_calculate_eflags_all(0xf<32>, Load(addr=0x4260bc0<32>, size=4, endness=Iend_LE), 0x0<32>, 0x0<32>) & 64 ))
        # since we only need the zero bit(indicated by the AND(..., 64)) we can eliminate the OR-ing of other flag bits to the result of x86g_calculate_eflags_all

        new_blocks = {}
        for node in ail_graph:
            if isinstance(node.statements[-1], Stmt.ConditionalJump):
                if isinstance(node.statements[-1].condition, Expr.BinaryOp) and node.statements[-1].condition.op == "CmpEQ" \
                        and isinstance(node.statements[-1].condition.operands[1], Expr.Const) and \
                        node.statements[-1].condition.operands[1].value == 0:

                    # Check if the outermost is AND with 64
                    if isinstance(node.statements[-1].condition.operands[0], Expr.BinaryOp) and \
                            node.statements[-1].condition.operands[0].op == "And" and isinstance(
                        node.statements[-1].condition.operands[0].operands[1], Expr.Const) and \
                            node.statements[-1].condition.operands[0].operands[1].value == 64:

                        if isinstance(node.statements[-1].condition.operands[0].operands[0], Expr.BinaryOp) and \
                                node.statements[-1].condition.operands[0].operands[0].op == "Or" and \
                                isinstance(node.statements[-1].condition.operands[0].operands[0].operands[0],
                                           Expr.BinaryOp) and \
                                node.statements[-1].condition.operands[0].operands[0].operands[0].op == "Or" and \
                                isinstance(
                                    node.statements[-1].condition.operands[0].operands[0].operands[0].operands[0],
                                    Expr.BinaryOp) and \
                                node.statements[-1].condition.operands[0].operands[0].operands[0].operands[
                                    0].op == "Or" and \
                                isinstance(node.statements[-1].condition.operands[0].operands[0].operands[0].operands[
                                               0].operands[0],
                                           Expr.BinaryOp) and \
                                node.statements[-1].condition.operands[0].operands[0].operands[0].operands[0].operands[
                                    0].op == "Or":
                            if node.statements[-1].condition.operands[0].operands[0].operands[0].operands[0].operands[
                                0].operands[0].dirty_expr.cee_name == "x86g_calculate_eflags_all":
                                idx = node.statements[-1].condition.operands[0].operands[0].operands[0].operands[
                                    0].operands[
                                    0].operands[0].idx
                                dirty_expr = node.statements[-1].condition.operands[0].operands[0].operands[0].operands[
                                    0].operands[
                                    0].operands[0].dirty_expr
                                bits = node.statements[-1].condition.operands[0].operands[0].operands[0].operands[
                                    0].operands[
                                    0].operands[0].bits
                                new_cond_stmt = Stmt.ConditionalJump(node.statements[-1].idx,
                                                                     condition=Expr.BinaryOp(
                                                                         node.statements[-1].condition.idx,
                                                                         "CmpEQ", (
                                                                             Expr.BinaryOp(
                                                                                 node.statements[-1].condition.operands[
                                                                                     0].idx,
                                                                                 "And", (
                                                                                     Expr.DirtyExpression(idx,
                                                                                                          dirty_expr,
                                                                                                          bits=bits),
                                                                                     node.statements[
                                                                                         -1].condition.operands[
                                                                                         0].operands[1]),
                                                                                 node.statements[-1].condition.operands[
                                                                                     0].signed,
                                                                                 **
                                                                                 node.statements[-1].condition.operands[
                                                                                     0].tags),
                                                                             node.statements[-1].condition.operands[1]),
                                                                         node.statements[-1].condition.signed,
                                                                         **node.statements[-1].condition.tags),
                                                                     true_target=node.statements[-1].true_target,
                                                                     false_target=node.statements[
                                                                         -1].false_target,
                                                                     **node.statements[-1].tags)

                                new_stmts = node.statements[:-1] + [new_cond_stmt]
                                new_block = node.copy()
                                new_block.statements = new_stmts
                                new_blocks[node] = new_block


        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()
                                                                         
        return ail_graph
    def separate_overlapping_blocks(self, ail_graph):
        # branch that have successors that share the same suffix instructions, we separate it out into a another block
        #
        #               node_a
        #                /\
        #           node_b node_c               node_b is a subset of node_c, with the same suffix insts
        #             /\    /\
        #            /  \  /  \
        #           /    \/    \
        #        node_d node_e node_d                    both node_d are the same node, just for representation they ahve been drawn as separate
        new_blocks = {}
        for node in ail_graph.nodes:
            skip_node = False
            succs = list(ail_graph.successors(node))
            if len(succs) == 2:

                l_succ = succs[0]
                r_succ = succs[1]

                #make sure that they merge immediatley to same succesors as well
                succs_succ_l = set(ail_graph.successors(l_succ))
                succs_succ_r = set(ail_graph.successors(r_succ))

                if succs_succ_l == succs_succ_r and len(l_succ.statements) != len(r_succ.statements):
                    # make sure all the statemetns in the smaller block match the statemetns in the bigger block
                    no_match_stmts = 0
                    for stmt_l, stmt_r in zip(reversed(l_succ.statements), reversed(r_succ.statements)):
                        #we do not check labels
                        if not isinstance(stmt_r, Stmt.Label) and not isinstance(stmt_l, Stmt.Label):
                            if not stmt_l.likes(stmt_r):
                                skip_node = True
                                break
                            no_match_stmts += 1

                    if skip_node:
                        continue

                    if len(l_succ.statements) < len(r_succ.statements):
                        non_match_idx = len(r_succ.statements)-no_match_stmts
                        new_stmts = r_succ.statements[:non_match_idx]

                        #if the remaining stmts have a tmp we cannot separate them
                        for stmt in new_stmts:
                            if isinstance(stmt, Stmt.Assignment) and isinstance(stmt.dst, Expr.Tmp):
                                skip_node = True
                                break

                        if skip_node:
                            continue

                        new_block = r_succ.copy()
                        new_block.statements = new_stmts

                        new_blocks[r_succ] = new_block

                        for succ_node in succs_succ_r:
                            ail_graph.remove_edge(r_succ, succ_node)

                        ail_graph.add_edge(r_succ, l_succ)

                    else:
                        non_match_idx = len(l_succ.statements) - no_match_stmts
                        new_stmts = l_succ.statements[:non_match_idx]

                        #if the remaining stmts have a tmp we cannot separate them from the other stmts
                        for stmt in new_stmts:
                            if isinstance(stmt, Stmt.Assignment) and isinstance(stmt.dst, Expr.Tmp):
                                skip_node = True
                                break
                        if skip_node:
                            continue

                        new_block = l_succ.copy()
                        new_block.statements = new_stmts

                        new_blocks[l_succ] = new_block

                        for succ_node in succs_succ_l:
                            ail_graph.remove_edge(l_succ, succ_node)

                        ail_graph.add_edge(l_succ, r_succ)

                    if skip_node:
                        continue

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

    def remove_redundant_conditional_check(self, ail_graph):
        # looking for this structure, where node_b  and node_c can be removed as node_c just sets a global var to 1 and
        # then node_b jumps to true branch if the global var is set. This happens in Themida
        #             node_k set g_var=0
        #               |
        #             node_a
        #              /\
        #             / node_c set g_var=1
        #             \  /
        #              \/
        #             node_b check g_var, if set jmp to node_d else jmp to node_e
        #              /\
        #        node_d  node_e
        #
        new_blocks = {}
        to_remove = set()
        rd = self.project.analyses.ReachingDefinitions(
            subject=self.function,
            func_graph=ail_graph,
            track_tmps=True,
            track_consts=False,
            # init_context=(),    <-- in case of fire break glass
            observe_all=False,
            use_callee_saved_regs_at_return=False,
            dep_graph=True
        )

        for node in ail_graph.nodes():
            succs = list(ail_graph.successors(node))
            if len(succs) == 2:
                global_const_addr = None
                for stmt in reversed(node.statements):
                    # check if the cur node sets global var to 0
                    if isinstance(stmt, ailment.statement.Store) and \
                            isinstance(stmt.addr, ailment.expression.Const) and \
                            isinstance(stmt.data, ailment.expression.Const) and \
                            stmt.data.value == 0:
                        global_const_addr = stmt.addr.value
                        break

                #check if the cur node sets global var to 0
                if global_const_addr:

                    l_succ = succs[0]
                    r_succ = succs[1]

                    merge_point_node = None

                    if len(list(ail_graph.successors(l_succ))) == 2 and len(list(ail_graph.successors(r_succ))) == 1:

                        #check if the left successor is successor fot the right branch
                        if list(ail_graph.successors(r_succ))[0] == l_succ:

                            # check if the right branch sets the globa var to 1
                            if isinstance(r_succ.statements[1], ailment.statement.Store) and \
                                    global_const_addr == r_succ.statements[1].addr.value and \
                                    isinstance(r_succ.statements[1].data, ailment.expression.Const) and \
                                    r_succ.statements[1].data.value == 1 and len(r_succ.statements) == 3:

                                global_store_stmt_idx = 1

                                #check if the left branch  has the second condtional check, and has only one statement(the check)
                                if len(l_succ.statements) == 2 and isinstance(l_succ.statements[1], ailment.statement.ConditionalJump) and \
                                    isinstance(l_succ.statements[1].condition, ailment.expression.BinaryOp):

                                    conditional_check_stmt_idx = 1

                                    codeloc = CodeLocation(r_succ.addr, global_store_stmt_idx, ins_addr=r_succ.statements[1].ins_addr)
                                    matom = atoms.MemoryLocation(addr=r_succ.statements[1].addr.value,
                                                                 size=r_succ.statements[1].size)

                                    defs = list(rd.model.get_defs(matom, codeloc, OP_AFTER))
                                    global_store_def = None
                                    for d in defs:
                                        if d.codeloc == codeloc:
                                            global_store_def = d
                                            break

                                    if not global_store_def:
                                        import ipdb;
                                        ipdb.set_trace()

                                    uses = list(rd.model.all_uses.get_uses(global_store_def))
                                    #make sure there are no other uses for this atom before removing the branches
                                    if len(uses) == 1 and uses[0].block_addr == l_succ.addr and uses[0].ins_addr == l_succ.statements[1].ins_addr and \
                                        uses[0].stmt_idx == conditional_check_stmt_idx:

                                        # check if the conditional check if cmpeq or neq
                                        if l_succ.statements[1].condition.op == "CmpEQ" and \
                                                isinstance(l_succ.statements[1].condition.operands[0], ailment.expression.Load) and \
                                                isinstance(l_succ.statements[1].condition.operands[0].addr, ailment.expression.Const) and \
                                                l_succ.statements[1].condition.operands[0].addr.value == global_const_addr and \
                                                isinstance(l_succ.statements[1].condition.operands[1], ailment.expression.Const) and \
                                                l_succ.statements[1].condition.operands[1].value == 0:

                                            if node.statements[-1].true_target.value == r_succ.addr:
                                                new_true_target = l_succ.statements[1].false_target
                                                new_false_target = l_succ.statements[1].true_target
                                            elif node.statements[-1].true_target.value == l_succ.addr:
                                                new_true_target = l_succ.statements[1].true_target
                                                new_false_target = l_succ.statements[1].false_target

                                            new_cond_stmt = Stmt.ConditionalJump(idx=None, condition=node.statements[-1].condition,
                                                                                 true_target=new_true_target,
                                                                                 false_target=new_false_target,
                                                                                 ins_addr=l_succ.statements[1].ins_addr,
                                                                                 vex_block_addr=l_succ.statements[1].vex_block_addr,
                                                                                 vex_stmt_idx=l_succ.statements[1].vex_stmt_idx,
                                                                                 )
                                            new_block = node.copy()
                                            new_stmts = node.statements[::]

                                            new_stmts[-1] = new_cond_stmt
                                            new_block.statements = new_stmts

                                            new_blocks[node] = new_block

                                            true_succs = list(ail_graph.successors(l_succ))
                                            ail_graph.add_edge(node, true_succs[0])
                                            ail_graph.add_edge(node, true_succs[1])

                                            to_remove.add(l_succ)
                                            to_remove.add(r_succ)

                                        elif l_succ.statements[1].condition.op == "CmpNE" and \
                                                isinstance(l_succ.statements[1].condition.operands[0],
                                                           ailment.expression.Load) and \
                                                isinstance(l_succ.statements[1].condition.operands[0].addr,
                                                           ailment.expression.Const) and \
                                                l_succ.statements[1].condition.operands[0].addr.value == global_const_addr and \
                                                isinstance(l_succ.statements[1].condition.operands[1],
                                                           ailment.expression.Const) and \
                                                l_succ.statements[1].condition.operands[1].value == 0:
                                            print("please implement")
                                            import ipdb;ipdb.set_trace()

                    elif len(list(ail_graph.successors(r_succ))) == 2 and len(list(ail_graph.successors(l_succ))) == 1:
                        if list(ail_graph.successors(l_succ))[0] == r_succ:
                            # check if the left branch sets the globa var to 1
                            if isinstance(l_succ.statements[1], ailment.statement.Store) and \
                                    global_const_addr == l_succ.statements[1].addr.value and \
                                    isinstance(l_succ.statements[1].data, ailment.expression.Const) and \
                                    l_succ.statements[1].data.value == 1:

                                global_store_stmt_idx = 1

                                # check if the right branch  has the second condtional check
                                if len(r_succ.statements) == 2 and isinstance(r_succ.statements[1],
                                                                              ailment.statement.ConditionalJump) and \
                                        isinstance(r_succ.statements[1].condition, ailment.expression.BinaryOp):

                                    conditional_check_stmt_idx = 1

                                    codeloc = CodeLocation(l_succ.addr, global_store_stmt_idx, ins_addr=l_succ.statements[1].ins_addr)
                                    matom = atoms.MemoryLocation(addr=l_succ.statements[1].addr.value,
                                                                 size=l_succ.statements[1].size)

                                    defs = list(rd.model.get_defs(matom, codeloc, OP_AFTER))
                                    global_store_def = None
                                    for d in defs:
                                        if d.codeloc == codeloc:
                                            global_store_def = d
                                            break

                                    if not global_store_def:
                                        import ipdb;ipdb.set_trace()

                                    uses = list(rd.model.all_uses.get_uses(global_store_def))
                                    #make sure there are no other uses for this atom before removing the branches
                                    if len(uses) == 1 and uses[0].block_addr == r_succ.addr and uses[0].ins_addr == r_succ.statements[1].ins_addr and \
                                        uses[0].stmt_idx == conditional_check_stmt_idx:

                                        # check if the conditional check if cmpeq or neq
                                        if r_succ.statements[1].condition.op == "CmpEQ" and \
                                                isinstance(r_succ.statements[1].condition.operands[0],
                                                           ailment.expression.Load) and \
                                                isinstance(r_succ.statements[1].condition.operands[0].addr,
                                                           ailment.expression.Const) and \
                                                r_succ.statements[1].condition.operands[
                                                    0].addr.value == global_const_addr and \
                                                isinstance(r_succ.statements[1].condition.operands[1],
                                                           ailment.expression.Const) and \
                                                r_succ.statements[1].condition.operands[1].value == 0:

                                            if node.statements[-1].true_target.value == l_succ.addr:
                                                new_true_target = r_succ.statements[1].false_target
                                                new_false_target = r_succ.statements[1].true_target
                                            elif node.statements[-1].true_target.value == r_succ.addr:
                                                new_true_target = r_succ.statements[1].true_target
                                                new_false_target = r_succ.statements[1].false_target

                                            new_cond_stmt = Stmt.ConditionalJump(idx=None,
                                                                                 condition=node.statements[-1].condition,
                                                                                 true_target=new_true_target,
                                                                                 false_target=new_false_target,
                                                                                 ins_addr=r_succ.statements[1].ins_addr,
                                                                                 vex_block_addr=r_succ.statements[
                                                                                     1].vex_block_addr,
                                                                                 vex_stmt_idx=r_succ.statements[
                                                                                     1].vex_stmt_idx,
                                                                                 )
                                            new_block = node.copy()
                                            new_stmts = node.statements[::]

                                            new_stmts[-1] = new_cond_stmt
                                            new_block.statements = new_stmts

                                            new_blocks[node] = new_block

                                            true_succs = list(ail_graph.successors(r_succ))
                                            ail_graph.add_edge(node, true_succs[0])
                                            ail_graph.add_edge(node, true_succs[1])

                                            to_remove.add(l_succ)
                                            to_remove.add(r_succ)


        for node in to_remove:
            ail_graph.remove_node(node)

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    def consecutive_store_load_across_blocks(self, ail_graph):
        # this handles a very specific case, in future replace with a more generic version
        new_blocks = {}
        for node in ail_graph.nodes():

            preds = list(pred for pred in ail_graph.predecessors(node) if pred is not node)
            succs = list(succ for succ in ail_graph.successors(node) if succ is not node)

            if len(preds) == 1 and len(succs) == 1:
                cur_succ = succs[0]
                succs_of_succ = list(succ for succ in ail_graph.successors(cur_succ) if succ is not cur_succ)
                preds_of_succs = list(succ for succ in ail_graph.predecessors(cur_succ) if succ is not cur_succ)

                if len(succs_of_succ) == 1 and len(preds_of_succs) == 1:

                    if isinstance(node.statements[-1], Stmt.Jump):
                        first_last_stmt = node.statements[-2]
                    else:
                        first_last_stmt = node.statements[-1]
                    if isinstance(cur_succ.statements[0], Stmt.Label):
                        second_first_stmt = cur_succ.statements[1]
                        second_idx = 1
                    else:
                        second_first_stmt = cur_succ.statements[0]
                        second_idx = 0

                    if isinstance(first_last_stmt, Stmt.Store) and \
                            isinstance(first_last_stmt.addr, Expr.Const) and \
                            isinstance(first_last_stmt.data, Expr.BinaryOp) and \
                            first_last_stmt.data.op == "Sub" and \
                            isinstance(first_last_stmt.data.operands[0], Expr.Load) and \
                            isinstance(first_last_stmt.data.operands[0].addr, Expr.Const) and \
                            isinstance(first_last_stmt.data.operands[1], Expr.Const) and \
                            first_last_stmt.addr.value != first_last_stmt.data.operands[0].addr.value:
                        # pattern match this
                        #STORE(addr=0x7ff6b5bfeba0<64>, data=(Load(addr=0x7ff6b5bfebe4<64>, size=8, endness=Iend_LE) - 0x330af03c<64>), size=8, endness=Iend_LE, guard=None)
                        first_store_size = first_last_stmt.data.size
                        first_store_addr = first_last_stmt.addr.value

                        to_replace_with_load_expr = first_last_stmt.data.operands[0]

                        if isinstance(second_first_stmt, Stmt.Assignment) and \
                            isinstance(second_first_stmt.src, Expr.BinaryOp) and \
                            second_first_stmt.src.op == "Add" and \
                            isinstance(second_first_stmt.src.operands[1], Expr.Const) and \
                            isinstance(second_first_stmt.src.operands[0], Expr.Load) and \
                            isinstance(second_first_stmt.src.operands[0].addr, Expr.Const):
                            # pattern match this
                            # rdi<8> = (Load(addr=0x7ff6b5bfeba0<64>, size=8, endness=Iend_LE) + 0x330af06c<64>)
                            second_load_addr = second_first_stmt.src.operands[0].addr.value
                            second_load_size = second_first_stmt.src.operands[0].size

                            if first_store_addr == second_load_addr and first_store_size == second_load_size:
                                simplified_offset = second_first_stmt.src.operands[1].value - first_last_stmt.data.operands[1].value
                                if simplified_offset > 0 and not second_first_stmt.src.signed and not first_last_stmt.data.signed:
                                    # simplify the arithmetic and replace the Load in the second stmt with the store in the first one
                                    new_expr = Expr.BinaryOp(None,
                                                             "Add",
                                                             [to_replace_with_load_expr, Expr.Const(None,
                                                                                                    None,
                                                                                                    simplified_offset,
                                                                                                    second_first_stmt.src.operands[1].bits)],
                                                             False)
                                    new_stmt = Stmt.Assignment(None, second_first_stmt.dst, new_expr, **second_first_stmt.tags)
                                    new_block = cur_succ.copy()
                                    new_stmts = cur_succ.statements[::]

                                    new_stmts[second_idx] = new_stmt
                                    new_block.statements = new_stmts

                                    new_blocks[cur_succ] = new_block

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    def remove_all_empty_nodes(self, ail_graph):
        def handle_node(node: ailment.Block):
            if (len(node.statements) == 1 and isinstance(node.statements[0], ailment.statement.Label)) or \
                (len(node.statements) == 2 and isinstance(node.statements[0], ailment.statement.Label) and \
                 isinstance(node.statements[1], ailment.statement.Jump)) or \
                    len(node.statements) == 0:
                preds = list(pred for pred in ail_graph.predecessors(node) if pred is not node)
                succs = list(succ for succ in ail_graph.successors(node) if succ is not node)
                if len(preds) == 1 and len(succs) == 1:
                    pred = preds[0]
                    succ = succs[0]

                    # update the last statement of pred
                    if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.Jump):
                        last_stmt = pred.statements[-1]
                        last_stmt.target = Expr.Const(None, succ.addr, last_stmt.target.bits)
                        ail_graph.add_edge(pred, succ)
                        raise RemoveNodeNotice()

                    # update the last statement of pred
                    elif pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                        value_updated = False
                        last_stmt = pred.statements[-1]
                        if (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and last_stmt.true_target.value == node.addr
                        ):
                            last_stmt.true_target = Expr.Const(None, succ.addr, last_stmt.true_target.bits)
                            value_updated = True
                        if (
                            isinstance(last_stmt.false_target, ailment.Expr.Const)
                            and last_stmt.false_target.value == node.addr
                        ):
                            last_stmt.false_target = Expr.Const(None, succ.addr, last_stmt.false_target.bits)
                            value_updated = True

                        if value_updated:
                            ail_graph.add_edge(pred, succ)
                            raise RemoveNodeNotice()
                    elif pred.statements and not isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                        ail_graph.add_edge(pred, succ)
                        raise RemoveNodeNotice()
                elif len(preds) ==2 and len(succs) == 1:
                    succ = succs[0]
                    edges_to_add = set()
                    for pred in preds:
                        # update the last statement of pred
                        if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.Jump):
                            last_stmt = pred.statements[-1]
                            last_stmt.target = Expr.Const(None, succ.addr, last_stmt.target.bits)
                            edges_to_add.add((pred, succ))

                        # update the last statement of pred
                        elif pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                            value_updated = False
                            last_stmt = pred.statements[-1]
                            if (
                                isinstance(last_stmt.true_target, ailment.Expr.Const)
                                and last_stmt.true_target.value == node.addr
                            ):
                                last_stmt.true_target = Expr.Const(None, succ.addr, last_stmt.true_target.bits)
                                value_updated = True
                            if (
                                isinstance(last_stmt.false_target, ailment.Expr.Const)
                                and last_stmt.false_target.value == node.addr
                            ):
                                last_stmt.false_target = Expr.Const(None, succ.addr, last_stmt.false_target.bits)
                                value_updated = True

                            if value_updated:
                                edges_to_add.add((pred, succ))
                        elif pred.statements and not isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                            edges_to_add.add((pred, succ))


                    for n1, n2 in edges_to_add:
                        ail_graph.add_edge(n1, n2)

                    raise RemoveNodeNotice()

                elif not preds or not succs:
                    raise RemoveNodeNotice()

        AILGraphWalker(ail_graph, handle_node, replace_nodes=True).walk()

        return ail_graph

    def themida_cond_simplification(self, ail_graph):
        # g_7ff6b5bfebf4 = [D]amd64g_calculate_rflags_all(0x8 < 64 >,
        #                           Load(addr=(Load(addr=0x7ff6b5bfebe4 < 64 >, size=8, endness=Iend_LE) + 0x20 < 64 >),
        #                                 size=8, endness=Iend_LE), 0xcdcfe0978055 < 64 >,
        #                            0x1 < 64 >) | v6 & 0x400 | v7 * 0x200000 & 0x200000 | v20 * 0x40000 & 0x40000;
        # if (!((char)g_7ff6b5bfebf4 & 64))
        #
        # simplify this to
        #
        # g_7ff6b5bfebf4 = [D]amd64g_calculate_rflags_all(0x8 < 64 >,
        #                           Load(addr=(Load(addr=0x7ff6b5bfebe4 < 64 >, size=8, endness=Iend_LE) + 0x20 < 64 >),
        #                                 size=8, endness=Iend_LE), 0xcdcfe0978055 < 64 >,
        #                            0x1 < 64 >);
        # if (!((char)g_7ff6b5bfebf4 & 64))

        from . import BlockSimplifier

        rd = self.project.analyses.ReachingDefinitions(
            subject=self.function,
            func_graph=ail_graph,
            observe_all=False,
            use_callee_saved_regs_at_return=True,
        ).model

        node_dict = {}
        for node in ail_graph.nodes():
            node_dict[node.addr] = node

        simp_cls = ThemidaCondSimplify2(self.project, self.kb, self.function.addr)

        new_blocks = {}
        for node in ail_graph:
            for stmt_idx, stmt in enumerate(node.statements):
                if isinstance(stmt, ailment.statement.ConditionalJump) and \
                        isinstance(stmt.condition, ailment.expression.BinaryOp) and\
                        stmt.condition.op == "CmpEQ" and \
                        isinstance(stmt.condition.operands[0], ailment.expression.BinaryOp) and \
                        stmt.condition.operands[0].op == "And" and \
                        isinstance(stmt.condition.operands[0].operands[0], ailment.expression.Load) and \
                        isinstance(stmt.condition.operands[0].operands[0].addr, ailment.expression.Const) and \
                        isinstance(stmt.condition.operands[0].operands[1], ailment.expression.Const) and \
                        stmt.condition.operands[0].operands[1].value == 64:

                    # this checks for jump condition like this, which means we only care about the zero bit, so we can remove all
                    # the arithmetic that affects the others bits from the def of g_7ff6b5bfebf4
                    # if (!((char)g_7ff6b5bfebf4 & 64))

                    codeloc = CodeLocation(node.addr, stmt_idx, ins_addr=stmt.tags['ins_addr'])
                    matom = atoms.MemoryLocation(addr=stmt.condition.operands[0].operands[0].addr.value,
                                                 size=stmt.condition.operands[0].operands[0].size)
                    cur_defs = list(rd.get_defs(matom, codeloc, OP_BEFORE))

                    if len(cur_defs) == 1:
                        cur_def = cur_defs[0]
                        def_node = node_dict[cur_def.codeloc.block_addr]
                        def_stmt = def_node.statements[cur_def.codeloc.stmt_idx]

                        if isinstance(def_stmt, ailment.statement.Store) and \
                            isinstance(def_stmt.addr, ailment.expression.Const):

                            def _handle_expr(
                                    expr_idx: int, expr, stmt_idx: int, stmt, block):
                                old_expr = expr

                                redo = True
                                while redo:
                                    redo = False
                                    if isinstance(expr, simp_cls.expr_classes):
                                        r = simp_cls.optimize(expr)
                                        if r is not None and r is not expr:
                                            expr = r
                                            redo = True
                                            break

                                if expr is not old_expr:
                                    # continue to process the expr
                                    r = AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)
                                    return expr if r is None else r

                                return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

                            # run expression optimizers
                            walker = AILBlockWalker()
                            walker._handle_expr = _handle_expr
                            new_operand_calc_flag = walker.walk_expression(
                                def_stmt.data)

                            if new_operand_calc_flag:
                                r, new_block = BlockSimplifier._replace_and_build(def_node,
                                                                                  {cur_def.codeloc:
                                                                                       {def_stmt.data: new_operand_calc_flag}}
                                )
                                new_blocks[def_node] = new_block

        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph


    def remove_same_branches(self, ail_graph):
        # this pass removes the branches that are semantically the same, keeping only one of them and remove the conditional check as well
        new_blocks = {}

        nodes_to_remove = set()
        for node in ail_graph.nodes():
            succs = list(ail_graph.successors(node))
            if len(succs) == 2:
                succ_0 = succs[0]
                succ_1 = succs[1]

                is_same = True
                if len(succ_0.statements) == len(succ_1.statements):
                    for i in range(1,len(succ_0.statements)): # skip the label
                        if not succ_0.statements[i].likes(succ_1.statements[i]):
                            is_same = False
                else:
                    is_same = False

                if is_same:
                    if len(list(ail_graph.successors(succ_0))) == 1 and len(list(ail_graph.successors(succ_1))) == 1 \
                            and list(ail_graph.successors(succ_0))[0] == list(ail_graph.successors(succ_1))[0]:
                        nodes_to_remove.add(succ_1)
                        if isinstance(node.statements[-1], ailment.statement.ConditionalJump):
                            new_stmts = node.statements[::]
                            new_stmts = new_stmts[:-1]
                            target_addr = ailment.Expr.Const(None, succ_0.addr, node.statements[-1].true_target.bits)
                            new_stmts.append(ailment.statement.Jump(None, target_addr, **node.statements[-1].tags))
                            #node.statements = new_stmts

                            new_block = node.copy()
                            new_block.statements = new_stmts
                            new_blocks[node] = new_block

        for node in nodes_to_remove:
            ail_graph.remove_node(node)

        #rebuild graph
        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph



    def _remove_cyclic_def_use(self, ail_graph):
        # This is an experimental dead assignment elimination for constant addr stores that are in a loop and
        # cannot be eliminated by regular dead assignment elimination because the last definition is used at the beginning of the loop.
        # In this we basically follow the def use chain for each const addr store and see if it ends up in a loop or not.
        # If it does end up in a loop then we can remove all these instructions, if not we do not remove them.
        # this indirectly check if a def ends up being used in a sink like a function argument or a branch condition
        # this analysis may have issues, as right now the use def edges inside a simprocedure are not added to the dep graph
        # so it is enough to check when no more uses are there for a def to assume that the use is a function/sink
        addr_and_idx_to_block = {}
        for block in ail_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block
        rd = self.project.analyses.ReachingDefinitions(
            subject=self.function,
            func_graph=ail_graph,
            track_tmps=True,
            track_consts=False,
            # init_context=(),    <-- in case of fire break glass
            observe_all=False,
            use_callee_saved_regs_at_return=False,
            dep_graph=True
        )

        possible_global_stores_to_remove = {}
        stmts_to_remove = defaultdict(set)

        def check_use_chain(def_node, root_def_node, visiting_nodes, completed_nodes):
            use_nodes = list(rd.dep_graph._graph.successors(def_node))

            if len(use_nodes) == 0:
                return False

            if def_node in completed_nodes:
                return completed_nodes[def_node]
            elif def_node in visiting_nodes:
                # This means there's a loop, so we can remove the def
                return True
            elif len(rd.all_uses.get_uses(def_node)) > len(use_nodes):
                # there is a use that that does not create a definition like in a guard for a jump or something else
                return False

            visiting_nodes[def_node] = True

            to_remove = True
            for use_node in use_nodes:
                to_remove = to_remove and check_use_chain(use_node, root_def_node, visiting_nodes, completed_nodes)

            # store the results so we don't calculate again and again
            completed_nodes[def_node] = to_remove
            visiting_nodes.pop(def_node)

            return to_remove

        for def_node in rd.dep_graph._graph.nodes():
            visiting_nodes = {}
            completed_nodes = {}
            if isinstance(def_node.codeloc, ExternalCodeLocation):
                continue
            # if already set to false then we do not remove the const address stores
            if def_node not in possible_global_stores_to_remove or possible_global_stores_to_remove[def_node]:
                if check_use_chain(def_node, def_node, visiting_nodes, completed_nodes):
                    possible_global_stores_to_remove[def_node] = True
                else:
                    possible_global_stores_to_remove[def_node] = False

        all_stmts_to_remove = set()
        for def_node in possible_global_stores_to_remove:
            if possible_global_stores_to_remove[def_node]:
                all_stmts_to_remove.add(def_node.codeloc)

        new_blocks = {}
        for block in ail_graph.nodes():
            new_statements = []
            for idx, stmt in enumerate(block.statements):
                codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.tags.get("ins_addr"), block_idx=block.idx)

                skip = False

                if (
                        isinstance(stmt, ailment.statement.Store) and isinstance(stmt.data, ailment.expression.Call)
                ) or (
                        isinstance(stmt, ailment.expression.Call)
                ):
                    skip = True

                if not skip and codeloc in all_stmts_to_remove:
                    continue

                new_statements.append(stmt)

            new_block = block.copy()
            new_block.statements = new_statements
            new_blocks[block] = new_block

        #rebuild graph
        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph


    def _remove_global_self_used_store(self, ail_graph):
        # This is an experimental dead assignment elimination for constant addr stores that are in a loop and
        # cannot be eliminated by regular dead assignment elimination because the last definition is used at the beginning of the loop.
        # In this we basically follow the def use chain for each const addr store and see if it ends up in a loop or not.
        # If it does end up in a loop then we can remove all these instructions, if not we do not remove them.
        # this indirectly check if a def ends up being used in a sink like a function argument or a branch condition
        # this analysis may have issues, as right now the use def edges inside a simprocedure are not added to the dep graph
        # so it is enough to check when no more uses are there for a def to assume that the use is a function/sink
        addr_and_idx_to_block = {}
        for block in ail_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block
        rd = self.project.analyses.ReachingDefinitions(
            subject=self.function,
            func_graph=ail_graph,
            track_tmps=True,
            track_consts=False,
            # init_context=(),    <-- in case of fire break glass
            observe_all=False,
            use_callee_saved_regs_at_return=False,
            dep_graph=True
        )

        possible_global_stores_to_remove = {}
        stmts_to_remove = defaultdict(set)

        def check_use_chain(def_node, root_def_node, visiting_nodes, completed_nodes):
            use_nodes = list(rd.dep_graph._graph.successors(def_node))

            if len(use_nodes) == 0:
                return False

            if def_node in completed_nodes:
                return completed_nodes[def_node]
            elif def_node in visiting_nodes:
                # This means there's a loop, so we can remove the def
                return True
            elif len(rd.all_uses.get_uses(def_node)) > len(use_nodes):
                # there is a use that that does not create a definition like in a guard for a jump or something else
                return False

            visiting_nodes[def_node] = True

            to_remove = True
            for use_node in use_nodes:
                if (
                        isinstance(use_node.atom, atoms.MemoryLocation) and isinstance(use_node.atom.addr, int)
                        and use_node.atom.addr == root_def_node.atom.addr
                ):
                    to_remove = to_remove and True
                else:
                    to_remove = to_remove and check_use_chain(use_node, root_def_node, visiting_nodes, completed_nodes)

            # store the results so we don't calculate again and again
            completed_nodes[def_node] = to_remove
            visiting_nodes.pop(def_node)

            return to_remove

        for def_node in rd.dep_graph._graph.nodes():
            if isinstance(def_node.atom, atoms.MemoryLocation) and isinstance(def_node.atom.addr, int):
                visiting_nodes = {}
                completed_nodes = {}
                # if already set to false then we do not remove the const address stores
                if def_node.atom.addr not in possible_global_stores_to_remove or possible_global_stores_to_remove[def_node.atom.addr]:
                    if check_use_chain(def_node, def_node, visiting_nodes, completed_nodes):
                        possible_global_stores_to_remove[def_node.atom.addr] = True
                        for node in completed_nodes:
                            stmts_to_remove[def_node.atom.addr].add(node.codeloc)
                    else:
                        possible_global_stores_to_remove[def_node.atom.addr] = False

        all_stmts_to_remove = set()
        for const_addr, loc in stmts_to_remove.items():
            if possible_global_stores_to_remove[const_addr]:
                all_stmts_to_remove.update(loc)

        new_blocks = {}
        for block in ail_graph.nodes():
            new_statements = []
            for idx, stmt in enumerate(block.statements):
                codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.tags.get("ins_addr"), block_idx=block.idx)
                if codeloc in all_stmts_to_remove:
                    continue

                new_statements.append(stmt)

            new_block = block.copy()
            new_block.statements = new_statements
            new_blocks[block] = new_block

        #rebuild graph
        def _handler(node):
            return new_blocks.get(node, None)

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    def simplify_vm_protect_mba_branching_condition(self, ail_graph, jump_addr_to_load_addr_map):
        for node in ail_graph.nodes():
            for stmt in node.statements:
                if isinstance(stmt, ailment.statement.Store) and isinstance(stmt.data, ailment.expression.BinaryOp) and stmt.data.op == "Shr" and isinstance(stmt.data.operands[1], ailment.expression.Const) and stmt.data.operands[1].value == 6:
                    jump_cond_load_addr_map = {}
                    #saved_stmt = stmt
                    saved_stmt = ailment.expression.Load(0, addr=stmt.addr, size=stmt.size, endness=stmt.endness)
                    cur_node = node
                    while not isinstance(cur_node.statements[-1], ailment.statement.ConditionalJump):
                        new_statements = []
                        for cur_node_stmt in cur_node.statements:
                            # skip the first Shr stmt i.e. skip the first stmt of the first node
                            if node is cur_node and stmt is cur_node_stmt:
                                new_statements.append(cur_node_stmt)
                                continue

                            # the first load address
                            if isinstance(cur_node_stmt, ailment.statement.Store) and isinstance(cur_node_stmt.data, ailment.expression.BinaryOp) \
                                    and cur_node_stmt.data.op == "Or" and isinstance(cur_node_stmt.data.operands[1], ailment.expression.Const):
                                # below ..not(addr)
                                load_addr = (1 << cur_node_stmt.data.operands[1].size*8) - 1 - cur_node_stmt.data.operands[1].value
                                ## check if this is the one that needs to be 1 for the branching condition to be true
                                ## if it is Binary op it is probably looking like this
                                #         v37 = !(v35) | !(v37); or v37 = !(v35) & !(v37);
                                #         v39 = !(v37) | -4358253;
                                # which means this condition needs to be 1 to use this address
                                if isinstance(list(ail_graph.predecessors(cur_node))[0].statements[-2].data, ailment.expression.BinaryOp):
                                    jump_cond_load_addr_map[load_addr] = 1
                                else:
                                    jump_cond_load_addr_map[load_addr] = 0

                            if isinstance(cur_node_stmt, ailment.statement.Store) and isinstance(cur_node_stmt.addr, ailment.expression.StackBaseOffset) and cur_node_stmt.addr.offset == saved_stmt.addr.offset:
                                continue
                            else:
                                new_statements.append(cur_node_stmt)
                        cur_node.statements = new_statements

                        cur_node = next(ail_graph.successors(cur_node))

                    # matching the destination jump address and the correct condition i.e. (x>>6 ==1) or (x>>6==0)
                    dst_jump_addr = cur_node.statements[-1].condition.operands[0].value
                    load_addr_from_analysis = jump_addr_to_load_addr_map[dst_jump_addr]

                    # we need to do this becasue the load addr we got during analysis is not the exact same as the one in vex they might be off by +-4 or +-8
                    jump_cond_to_use = None
                    for load_addr_from_vex, jump_cond in jump_cond_load_addr_map.items():
                        if abs(load_addr_from_analysis-load_addr_from_vex) <= 8:
                            jump_cond_to_use = jump_cond


                    new_stmt = ailment.expression.BinaryOp(cur_node.statements[-1].condition.idx,
                                                           cur_node.statements[-1].condition.op,
                                                           (saved_stmt, ailment.expression.Const(None, None, jump_cond_to_use, self.project.arch.bits)),
                                                           cur_node.statements[-1].condition.signed)
                    cur_node.statements[-1].condition = new_stmt

        return ail_graph
