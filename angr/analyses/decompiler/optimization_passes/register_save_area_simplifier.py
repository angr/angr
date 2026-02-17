# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from collections import defaultdict
from collections.abc import Iterable
from itertools import chain
import logging

import archinfo
import angr.ailment as ailment

from angr.calling_conventions import SimRegArg
from angr.code_location import CodeLocation
from angr.analyses.decompiler.stack_item import StackItem, StackItemType
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class RegisterSaveAreaSimplifier(OptimizationPass):
    """
    Optimizes away register spilling effects, including callee-saved registers.

    This optimization runs between SSA-level0 and SSA-level1, which means registers are converted to vvars but stack
    accesses stay unchanged.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Simplify register save areas"
    DESCRIPTION = __doc__.strip()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.analyze()

    def _check(self):
        # Check the first block to see what external registers are stored on the stack
        stored_info = self._find_registers_stored_on_stack()
        if not stored_info:
            return False, None

        # Check all return sites to see what external registers are restored to registers from the stack
        restored_info = self._find_registers_restored_from_stack()
        if not restored_info:
            return False, None

        # Find common registers and stack offsets
        info = self._intersect_register_info(stored_info, restored_info)

        return bool(info), {"info": info}

    def _analyze(self, cache=None):
        if cache is None:
            return

        info: dict[int, dict[str, list[tuple[int, CodeLocation]]]] = cache["info"]
        updated_blocks: defaultdict[ailment.Block, set[int]] = defaultdict(set)

        for data in info.values():
            # remove storing statements
            for _, codeloc in chain(data["stored"], data["restored"]):
                old_block = self._get_block(codeloc.block_addr, idx=codeloc.block_idx)
                assert old_block is not None
                updated_blocks[old_block].add(codeloc.stmt_idx)

        for old_block, removed_indices in updated_blocks.items():
            # remove all marked statements
            statements = [stmt for idx, stmt in enumerate(old_block.statements) if idx not in removed_indices]
            new_block = old_block.copy(statements=statements)
            # update it
            self._update_block(old_block, new_block)

        if updated_blocks:
            # update stack_items
            for data in info.values():
                for stack_offset, _ in data["stored"]:
                    self.stack_items[stack_offset] = StackItem(
                        stack_offset, self.project.arch.bytes, "regs", StackItemType.SAVED_REGS
                    )

    def _find_registers_stored_on_stack(self) -> list[tuple[int, int, CodeLocation]]:
        first_block = self._get_block(self._func.addr)
        if first_block is None:
            return []

        results = []

        # there are cases where sp is moved to another register at the beginning of the function before it is
        # subtracted, then it is used for stack accesses.
        # for example:
        # 132B0 mov     r11, rsp
        # 132B3 sub     rsp, 88h
        # 132BA ...
        # 132C1 ...
        # 132C6 mov     [r11-18h], r13
        # 132CA mov     [r11-20h], r14
        # we support such cases because we will have rewritten r11-18h to SpOffset(-N) when this optimization runs.

        # identify which registers have been updated in this function; they are no longer saved
        ignored_regs: set[int] = set()

        for idx, stmt in enumerate(first_block.statements):
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.was_reg
            ):
                ignored_regs.add(stmt.dst.reg_offset)
            if (
                isinstance(stmt, ailment.Stmt.Store)
                and isinstance(stmt.addr, ailment.Expr.StackBaseOffset)
                and isinstance(stmt.addr.offset, int)
            ):
                reg_offset = None
                if isinstance(stmt.data, ailment.Expr.VirtualVariable) and stmt.data.was_reg:
                    reg_offset = stmt.data.reg_offset
                elif (
                    self.project.arch.name == "AMD64"
                    and isinstance(stmt.data, ailment.Expr.Extract)
                    and isinstance(stmt.data.offset, ailment.Expr.Const)
                    and isinstance(stmt.data.offset.value, int)
                    and isinstance(stmt.data.base, ailment.Expr.VirtualVariable)
                    and stmt.data.base.was_reg
                    and stmt.data.base.bits == 256
                    and stmt.data.bits == 128
                ):
                    # xmm registers extracted from ymm registers
                    reg_offset = stmt.data.base.reg_offset + stmt.data.offset.value

                if reg_offset is not None and reg_offset not in ignored_regs:
                    # it's storing registers to the stack!
                    stack_offset = stmt.addr.offset
                    codeloc = CodeLocation(
                        first_block.addr, idx, block_idx=first_block.idx, ins_addr=stmt.tags.get("ins_addr", None)
                    )
                    results.append((reg_offset, stack_offset, codeloc))

        return results

    def _find_registers_restored_from_stack(self) -> list[list[tuple[int, int, CodeLocation]]]:
        all_results = []
        for ret_site in self._func.ret_sites + self._func.jumpout_sites:
            ret_blocks = list(self._get_blocks(ret_site.addr))
            if len(ret_blocks) == 1 and self.project.simos is not None and self.project.simos.name == "Win32":
                # PE files may call __security_check_cookie (which terminates the program if the stack canary is
                # corrupted) before returning.
                preds = list(self._graph.predecessors(ret_blocks[0]))
                if len(preds) == 1:
                    pred = preds[0]
                    if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.SideEffectStatement):
                        last_stmt = pred.statements[-1]
                        if isinstance(last_stmt.expr.target, ailment.Expr.Const):
                            callee_addr = last_stmt.expr.target.value
                            if self.project.kb.functions.contains_addr(callee_addr):
                                callee_func = self.project.kb.functions.get_by_addr(callee_addr)
                                if callee_func.name == "_security_check_cookie":
                                    ret_blocks.append(pred)

            for block in ret_blocks:
                results = []
                for idx, stmt in enumerate(block.statements):
                    if (
                        isinstance(stmt, ailment.Stmt.Assignment)
                        and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                        and stmt.dst.was_reg
                    ):
                        reg_offset = stmt.dst.reg_offset
                        stack_offset = None
                        if isinstance(stmt.src, ailment.Expr.Load) and isinstance(
                            stmt.src.addr, ailment.Expr.StackBaseOffset
                        ):
                            stack_offset = stmt.src.addr.offset
                        elif (
                            isinstance(stmt.src, ailment.Expr.Insert)
                            and isinstance(stmt.src.offset, ailment.Expr.Const)
                            and isinstance(stmt.src.offset.value, int)
                            and isinstance(stmt.src.value, ailment.Expr.Load)
                            and isinstance(stmt.src.value.addr, ailment.Expr.StackBaseOffset)
                        ):
                            stack_offset = stmt.src.value.addr.offset
                            reg_offset += stmt.src.offset.value

                        if stack_offset is not None:
                            codeloc = CodeLocation(
                                block.addr, idx, block_idx=block.idx, ins_addr=stmt.tags.get("ins_addr", None)
                            )
                            results.append((reg_offset, stack_offset, codeloc))

                if results:
                    all_results.append(results)

        return all_results

    def _intersect_register_info(
        self,
        stored: list[tuple[int, int, CodeLocation]],
        restored: Iterable[list[tuple[int, int, CodeLocation]]],
    ) -> dict[int, dict[str, list[tuple[int, CodeLocation]]]]:
        def _collect(info: list[tuple[int, int, CodeLocation]], output, keystr: str):
            for reg_offset, stack_offset, codeloc in info:
                if reg_offset not in output:
                    output[reg_offset] = {}
                if keystr not in output[reg_offset]:
                    output[reg_offset][keystr] = []
                output[reg_offset][keystr].append((stack_offset, codeloc))

        result: dict[int, dict[str, list[tuple[int, CodeLocation]]]] = {}
        _collect(stored, result, "stored")
        for item in restored:
            _collect(item, result, "restored")

        # remove registers that are
        # (a) stored but not restored
        # (b) restored but not stored
        # (c) from different offsets
        # (d) the same as the return value register

        cc = self._func.calling_convention
        if cc is not None and isinstance(cc.RETURN_VAL, SimRegArg):
            ret_val_reg_offset = self.project.arch.registers[cc.RETURN_VAL.reg_name][0]
        else:
            ret_val_reg_offset = None

        # link register
        if archinfo.arch_arm.is_arm_arch(self.project.arch):
            lr_reg_offset = self.project.arch.registers["lr"][0]
        elif self.project.arch.name in {"MIPS32", "MIPS64"}:
            lr_reg_offset = self.project.arch.registers["ra"][0]
        elif self.project.arch.name in {"PPC32", "PPC64"} or self.project.arch.name.startswith("PowerPC:"):
            lr_reg_offset = self.project.arch.registers["lr"][0]
        else:
            lr_reg_offset = None

        for reg in list(result.keys()):
            # stored link register should always be removed
            if lr_reg_offset is not None and reg == lr_reg_offset:
                if "restored" not in result[reg]:
                    # add a dummy one
                    result[reg]["restored"] = []
                continue

            if ret_val_reg_offset is not None and reg == ret_val_reg_offset:
                # (d)
                del result[reg]
                continue

            info = result[reg]
            if len(info.keys()) != 2:
                # (a) or (b)
                del result[reg]
                continue

            stack_offsets = {stack_offset for stack_offset, _ in info["stored"]} | {
                stack_offset for stack_offset, _ in info["restored"]
            }

            if len(stack_offsets) != 1:
                # (c)
                del result[reg]
                continue

        return result
