# pylint:disable=too-many-boolean-expressions
from typing import Optional

import capstone

from angr.knowledge_plugins.functions import Function


def is_function_security_check_cookie(func, project, security_cookie_addr: int) -> bool:
    # disassemble the first instruction
    if func.is_plt or func.is_syscall or func.is_simprocedure:
        return False
    block = project.factory.block(func.addr)
    if block.instructions != 2:
        return False
    ins0 = block.capstone.insns[0]
    if (
        ins0.mnemonic == "cmp"
        and len(ins0.operands) == 2
        and ins0.operands[0].type == capstone.x86.X86_OP_REG
        and ins0.operands[0].reg == capstone.x86.X86_REG_RCX
        and ins0.operands[1].type == capstone.x86.X86_OP_MEM
        and ins0.operands[1].mem.base == capstone.x86.X86_REG_RIP
        and ins0.operands[1].mem.index == 0
        and ins0.operands[1].mem.disp + ins0.address + ins0.size == security_cookie_addr
    ):
        ins1 = block.capstone.insns[1]
        if ins1.mnemonic == "jne":
            return True
    return False


def is_function_security_init_cookie(func: "Function", project, security_cookie_addr: Optional[int]) -> bool:
    if func.is_plt or func.is_syscall or func.is_simprocedure:
        return False
    # the function should have only one return point
    if len(func.endpoints) == 1 and len(func.ret_sites) == 1:
        # the function is normalized
        ret_block = next(iter(func.ret_sites))
        preds = [(pred.addr, pred.size) for pred in func.graph.predecessors(ret_block)]
        if len(preds) != 2:
            return False
    elif len(func.endpoints) == 2 and len(func.ret_sites) == 2:
        # the function is not normalized
        ep0, ep1 = func.endpoints
        if ep0.addr > ep1.addr:
            ep0, ep1 = ep1, ep0
        if ep0.addr + ep0.size == ep1.addr + ep1.size and ep0.addr < ep1.addr:
            # overlapping block
            preds = [(ep0.addr, ep1.addr - ep0.addr)]
        else:
            return False
    else:
        return False
    for node_addr, node_size in preds:
        # lift the block and check the last instruction
        block = project.factory.block(node_addr, size=node_size)
        if not block.instructions:
            continue
        last_insn = block.capstone.insns[-1]
        if (
            last_insn.mnemonic == "mov"
            and len(last_insn.operands) == 2
            and last_insn.operands[0].type == capstone.x86.X86_OP_MEM
            and last_insn.operands[0].mem.base == capstone.x86.X86_REG_RIP
            and last_insn.operands[0].mem.index == 0
            and last_insn.operands[0].mem.disp + last_insn.address + last_insn.size == security_cookie_addr
            and last_insn.operands[1].type == capstone.x86.X86_OP_REG
        ):
            return True
    return False


def is_function_security_init_cookie_win8(func: "Function", project, security_cookie_addr: int) -> bool:
    # disassemble the first instruction
    if func.is_plt or func.is_syscall or func.is_simprocedure:
        return False
    block = project.factory.block(func.addr)
    if block.instructions != 3:
        return False
    ins0 = block.capstone.insns[0]
    if (
        ins0.mnemonic == "mov"
        and len(ins0.operands) == 2
        and ins0.operands[0].type == capstone.x86.X86_OP_REG
        and ins0.operands[0].reg == capstone.x86.X86_REG_RAX
        and ins0.operands[1].type == capstone.x86.X86_OP_MEM
        and ins0.operands[1].mem.base == capstone.x86.X86_REG_RIP
        and ins0.operands[1].mem.index == 0
        and ins0.operands[1].mem.disp + ins0.address + ins0.size == security_cookie_addr
    ):
        ins1 = block.capstone.insns[-1]
        if ins1.mnemonic == "je":
            succs = list(func.graph.successors(func.get_node(block.addr)))
            if len(succs) > 2:
                return False
            for succ in succs:
                succ_block = project.factory.block(succ.addr)
                if succ_block.instructions:
                    first_insn = succ_block.capstone.insns[0]
                    if (
                        first_insn.mnemonic == "movabs"
                        and len(first_insn.operands) == 2
                        and first_insn.operands[1].type == capstone.x86.X86_OP_IMM
                        and first_insn.operands[1].imm == 0x2B992DDFA232
                    ):
                        return True
    return False


def is_function_likely_security_init_cookie(func: "Function") -> bool:
    """
    Conducts a fuzzy match for security_init_cookie function.
    """

    callees = [node for node in func.transition_graph if isinstance(node, Function)]
    callee_names = {callee.name for callee in callees}
    if callee_names.issuperset(
        {
            "GetSystemTimeAsFileTime",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "GetTickCount",
            "QueryPerformanceCounter",
        }
    ):
        return True
    return False
