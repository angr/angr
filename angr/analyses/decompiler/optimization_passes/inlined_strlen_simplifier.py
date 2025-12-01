# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from typing import Any

from angr.ailment import Block
from angr.ailment.statement import Assignment, Label, ConditionalJump, Call
from angr.ailment.expression import BinaryOp, VirtualVariable, Const, Phi, Load, Expression
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.utils.ail import is_phi_assignment
from angr.utils.bits import u2s


class InlinedStrlenSimplifier(OptimizationPass):
    """
    Abstracts inlined strlen functions into strlen() calls.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Identify and simplify inlined strlen() functions"
    DESCRIPTION = "Identify and simplify inlined strlen() functions"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        strlen_descs = self._find_strlen_patterns()

        return bool(strlen_descs), {"descs": strlen_descs}

    def _analyze(self, cache=None):
        if not cache or "descs" not in cache:
            return

        blocks_dict = {(block.addr, block.idx): block for block in self._graph}

        for desc in cache["descs"]:
            self._convert_block_to_strlen(
                blocks_dict[(desc["block_addr"], desc["block_idx"])], desc["str"], desc["result_var"], desc["load_size"]
            )

    def _convert_block_to_strlen(
        self, block: Block, str_expr: Expression, result_var: VirtualVariable, load_size: int
    ) -> None:
        """
        Convert the given block into a strlen() call.
        """

        match load_size:
            case 1:
                func_name = "strlen"
            case 2:
                func_name = "wcslen"
            case _:
                raise RuntimeError(f"Unsupported load size {load_size} for strlen simplification.")
        strlen_call = Call(None, func_name, args=[str_expr], ret_expr=None, bits=result_var.bits, ins_addr=block.addr)
        strlen_stmt = Assignment(None, result_var, strlen_call, ins_addr=block.addr)
        new_block = Block(block.addr, block.original_size, statements=[strlen_stmt], idx=block.idx)
        self._update_block(block, new_block)

        # remove the self-loop edge
        assert self.out_graph is not None
        if self.out_graph.has_edge(new_block, new_block):
            self.out_graph.remove_edge(new_block, new_block)

    def _find_strlen_patterns(self):
        """
        Identify strlen patterns.
        """

        blocks_dict = {(block.addr, block.idx): block for block in self._graph}
        strlen_descs = []

        for block in self._graph:
            r, d = self._is_strlen_pattern_1_core_block(block)
            if r:
                assert d is not None
                if d["load_size"] in {1, 2}:
                    # ensure the index variable is initialized to -1
                    index_var_src: tuple[int, int | None] = d["index_var_src"]
                    index_var: VirtualVariable = d["index_var"]

                    index_var_init_value = self._find_var_init_value(blocks_dict[index_var_src], index_var)
                    if (
                        index_var_init_value is not None
                        and isinstance(index_var_init_value, Const)
                        and u2s(index_var_init_value.value_int, index_var.bits) == -1
                    ):
                        strlen_descs.append(d)
        return strlen_descs

    @staticmethod
    def _is_strlen_pattern_1_core_block(block: Block) -> tuple[bool, dict[str, Any] | None]:
        """
        Pattern 1:

        ## Block 1400145ee
        00 | 0x1400145ee | vvar_403{r16|8b} = 𝜙@64b [((5368792551, None), vvar_1507{r16|8b}), ((5368792558, None),
                vvar_1509{r16|8b})]
        01 | 0x1400145ee | LABEL_1400145ee:
        02 | 0x1400145ee | vvar_1509{r16|8b} = (vvar_403{r16|8b} + 0x1<64>)
        03 | 0x1400145f4 | if ((Load(addr=(vvar_394{r40|8b} + vvar_1509{r16|8b}), size=1, endness=Iend_LE) == 0x0<8>))
                { Goto 0x1400145f6<64> } else { Goto 0x1400145ee<64> }

        this method only verifies if the given block follows the pattern of the strlen core block; it does not verify
        if the index variable is properly initialized to -1.
        """

        phi_stmt: Assignment | None = None
        assignment_stmt: Assignment | None = None
        cond_jump: ConditionalJump | None = None
        for stmt in block.statements:
            if is_phi_assignment(stmt):
                if phi_stmt is not None:
                    return False, None
                phi_stmt = stmt  # type: ignore
            elif isinstance(stmt, Label):
                continue
            elif isinstance(stmt, Assignment):
                if assignment_stmt is not None:
                    return False, None
                assignment_stmt = stmt
            elif isinstance(stmt, ConditionalJump):
                if cond_jump is not None:
                    return False, None
                cond_jump = stmt
            else:
                return False, None

        if phi_stmt is None or assignment_stmt is None or cond_jump is None:
            return False, None

        v0 = phi_stmt.dst

        # check the assignment statement
        v1 = assignment_stmt.dst
        if isinstance(assignment_stmt.src, BinaryOp) and assignment_stmt.src.op == "Add":
            binop: BinaryOp = assignment_stmt.src
            if (
                isinstance(binop.operands[0], VirtualVariable)
                and binop.operands[0].likes(v0)
                and isinstance(binop.operands[1], Const)
                and binop.operands[1].value == 1
            ) or (
                isinstance(binop.operands[1], VirtualVariable)
                and binop.operands[1].likes(v0)
                and isinstance(binop.operands[0], Const)
                and binop.operands[0].value == 1
            ):
                pass
            else:
                return False, None
        else:
            return False, None

        if v0.likes(v1):
            # unexpected due to SSA but still gotta check
            return False, None

        # check the phi statement
        v_phi_src_var: VirtualVariable | None = None
        v_phi_src: tuple[int, int | None] | None = None
        assert isinstance(phi_stmt.src, Phi)
        if len(phi_stmt.src.src_and_vvars) == 2:
            src_to_vvars = dict(phi_stmt.src.src_and_vvars)
            if (block.addr, block.idx) not in src_to_vvars:
                return False, None
            vvar = src_to_vvars[(block.addr, block.idx)]
            if vvar is not None and vvar.likes(v1):
                # self-loop
                v_phi_src, v_phi_src_var = next(
                    (src, vvar) for src, vvar in phi_stmt.src.src_and_vvars if src != (block.addr, block.idx)
                )
            else:
                return False, None
        else:
            return False, None

        assert v_phi_src is not None and v_phi_src_var is not None

        # check the conditional jump
        cond = cond_jump.condition
        if (
            isinstance(cond, BinaryOp)
            and cond.op in {"CmpEQ", "CmpNE"}
            and isinstance(cond.operands[0], Load)
            and isinstance(cond.operands[1], Const)
            and cond.operands[1].value == 0
        ):
            load_addr = cond.operands[0].addr
            load_size = cond.operands[0].size
            str_src = None
            r = False
            if (
                isinstance(load_addr, BinaryOp)
                and load_addr.op == "Add"
                and any(op.likes(v1) for op in load_addr.operands)
                and load_size == 1
            ):
                str_src = next(op for op in load_addr.operands if not op.likes(v1))
                if (
                    cond.op == "CmpEQ"
                    and isinstance(cond_jump.false_target, Const)
                    and cond_jump.false_target.value == block.addr
                    and cond_jump.false_target_idx == block.idx
                    and isinstance(cond_jump.true_target, Const)
                    and (cond_jump.true_target.value, cond_jump.true_target_idx) != (block.addr, block.idx)
                ) or (
                    cond.op == "CmpNE"
                    and isinstance(cond_jump.true_target, Const)
                    and cond_jump.true_target.value == block.addr
                    and cond_jump.true_target_idx == block.idx
                    and isinstance(cond_jump.false_target, Const)
                    and (cond_jump.false_target.value, cond_jump.false_target_idx) != (block.addr, block.idx)
                ):
                    r = True

            elif (
                isinstance(load_addr, BinaryOp)
                and load_addr.op == "Add"
                and isinstance(load_addr.operands[1], BinaryOp)
                and load_addr.operands[1].op == "Mul"
            ):
                mul_op: BinaryOp = load_addr.operands[1]
                if (
                    isinstance(mul_op.operands[0], VirtualVariable)
                    and mul_op.operands[0].likes(v1)
                    and isinstance(mul_op.operands[1], Const)
                    and mul_op.operands[1].value == load_size
                ):
                    str_src = load_addr.operands[0]
                    r = False
                    if (
                        cond.op == "CmpEQ"
                        and isinstance(cond_jump.false_target, Const)
                        and cond_jump.false_target.value == block.addr
                        and cond_jump.false_target_idx == block.idx
                        and isinstance(cond_jump.true_target, Const)
                        and (cond_jump.true_target.value, cond_jump.true_target_idx) != (block.addr, block.idx)
                    ) or (
                        cond.op == "CmpNE"
                        and isinstance(cond_jump.true_target, Const)
                        and cond_jump.true_target.value == block.addr
                        and cond_jump.true_target_idx == block.idx
                        and isinstance(cond_jump.false_target, Const)
                        and (cond_jump.false_target.value, cond_jump.false_target_idx) != (block.addr, block.idx)
                    ):
                        r = True

            if r:
                return True, {
                    "block_addr": block.addr,
                    "block_idx": block.idx,
                    "str": str_src,
                    "index_var": v_phi_src_var,
                    "index_var_src": v_phi_src,
                    "load_size": load_size,
                    "result_var": v1,
                }

        return False, None

    @staticmethod
    def _find_var_init_value(block: Block, var: VirtualVariable) -> Expression | None:
        """
        Find the initialization value of a variable in a block.
        """

        for stmt in block.statements:
            if isinstance(stmt, Assignment) and stmt.dst.likes(var):
                return stmt.src
        return None
