# pylint:disable=arguments-differ,too-many-boolean-expressions
from __future__ import annotations

from angr.ailment import Const
from angr.ailment.expression import BinaryOp, Load, Expression, Tmp
from angr.ailment.statement import CAS, ConditionalJump, Statement, Assignment, Call

from .base import PeepholeOptimizationMultiStmtBase


_INTRINSICS_NAMES = {
    "xchg8": {"Win32": "InterlockedExchange8", "Linux": "atomic_exchange"},
    "xchg16": {"Win32": "InterlockedExchange16", "Linux": "atomic_exchange"},
    "xchg32": {"Win32": "InterlockedExchange", "Linux": "atomic_exchange"},
    "xchg64": {"Win32": "InterlockedExchange64", "Linux": "atomic_exchange"},
    "cmpxchg16": {"Win32": "InterlockedCompareExchange16", "Linux": "atomic_compare_exchange"},
    "cmpxchg32": {"Win32": "InterlockedCompareExchange", "Linux": "atomic_compare_exchange"},
    "cmpxchg64": {"Win32": "InterlockedCompareExchange64", "Linux": "atomic_compare_exchange"},
    "cmpxchg128": {"Win32": "InterlockedCompareExchange128", "Linux": "atomic_compare_exchange"},
    "lock_inc16": {"Win32": "InterlockedIncrement16", "Linux": "atomic_fetch_add"},
    "lock_inc32": {"Win32": "InterlockedIncrement", "Linux": "atomic_fetch_add"},
    "lock_inc64": {"Win32": "InterlockedIncrement64", "Linux": "atomic_fetch_add"},
    "lock_dec16": {"Win32": "InterlockedDecrement16", "Linux": "atomic_fetch_dec"},
    "lock_dec32": {"Win32": "InterlockedDecrement", "Linux": "atomic_fetch_dec"},
    "lock_dec64": {"Win32": "InterlockedDecrement64", "Linux": "atomic_fetch_dec"},
    "lock_xadd32": {"Win32": "InterlockedExchangeAdd", "Linux": "atomic_exchange_add"},
    "lock_xadd64": {"Win32": "InterlockedExchangeAdd64", "Linux": "atomic_exchange_add"},
}


class CASIntrinsics(PeepholeOptimizationMultiStmtBase):
    """
    Rewrite lock-prefixed instructions (or rather, their VEX/AIL forms) into intrinsic calls.

    Case 1.

                 mov eax, r12d
    0x140014b57: xchg eax, [0x14000365f8]

    LABEL_0x140014b57:
    CAS(0x1400365f8<64>, Conv(64->32, vvar_365{reg 112}), Load(addr=0x1400365f8<64>, size=4, endness=Iend_LE),
        vvar_27756)
    if (CasCmpNE(vvar_27756, g_1400365f8))
        goto LABEL_0x140014b57;

    => vvar_27756 = _InterlockedExchange(0x1400365f8, vvar_365{reg 112})


    Case 2.

    lock cmpxchg cs:g_WarbirdSecureFunctionsLock, r14d

    CAS(0x1400365f8<64>, 0x1<32>, 0x0<32>, vvar_27751)

    => var_27751 = _InterlockedCompareExchange(0x1400365f8, 0x1<32>, 0x0<32>)
    """

    __slots__ = ()

    NAME = "Rewrite compare-and-swap instructions into intrinsics."
    stmt_classes = ((CAS, ConditionalJump), (CAS, Statement))

    def optimize(self, stmts: list[Statement], stmt_idx: int | None = None, block=None, **kwargs):
        assert len(stmts) == 2
        cas_stmt = stmts[0]
        next_stmt = stmts[1]
        assert isinstance(cas_stmt, CAS)

        # TODO: We ignored endianness. Are there cases where the endianness is different from the host's?

        if (
            isinstance(next_stmt, ConditionalJump)
            and isinstance(next_stmt.condition, BinaryOp)
            and next_stmt.condition.op == "CasCmpNE"
            and next_stmt.ins_addr == cas_stmt.ins_addr
        ):
            addr = cas_stmt.addr
            expd_lo = self._resolve_tmp_expr(cas_stmt.expd_lo, block)
            next_stmt_cond_op1 = self._resolve_tmp_expr(next_stmt.condition.operands[1], block)
            if (
                isinstance(expd_lo, Load)
                and expd_lo.addr.likes(addr)
                and isinstance(next_stmt_cond_op1, Load)
                and next_stmt_cond_op1.addr.likes(addr)
                and cas_stmt.old_lo.likes(next_stmt.condition.operands[0])
                and cas_stmt.old_hi is None
            ):
                # TODO: Support cases where cas_stmt.old_hi is not None
                # Case 1

                call_expr = None
                if isinstance(cas_stmt.data_lo, BinaryOp):
                    if cas_stmt.data_lo.op == "Add" and cas_stmt.data_lo.operands[0].likes(cas_stmt.expd_lo):
                        if isinstance(cas_stmt.data_lo.operands[1], Const) and cas_stmt.data_lo.operands[1].value == 1:
                            # lock inc
                            call_expr = Call(
                                cas_stmt.idx,
                                self._get_instrincs_name(f"lock_inc{cas_stmt.bits}"),
                                args=[cas_stmt.addr],
                                bits=cas_stmt.bits,
                                ins_addr=cas_stmt.ins_addr,
                            )
                        else:
                            # lock xadd
                            call_expr = Call(
                                cas_stmt.idx,
                                self._get_instrincs_name(f"lock_xadd{cas_stmt.bits}"),
                                args=[cas_stmt.addr, cas_stmt.data_lo.operands[1]],
                                bits=cas_stmt.bits,
                                ins_addr=cas_stmt.ins_addr,
                            )
                    elif (
                        cas_stmt.data_lo.op == "Sub"
                        and cas_stmt.data_lo.operands[0].likes(cas_stmt.expd_lo)
                        and isinstance(cas_stmt.data_lo.operands[1], Const)
                        and cas_stmt.data_lo.operands[1].value == 1
                    ):
                        # lock dec
                        call_expr = Call(
                            cas_stmt.idx,
                            self._get_instrincs_name(f"lock_dec{cas_stmt.bits}"),
                            args=[cas_stmt.addr],
                            bits=cas_stmt.bits,
                            ins_addr=cas_stmt.ins_addr,
                        )

                if call_expr is None:
                    call_expr = Call(
                        cas_stmt.idx,
                        self._get_instrincs_name(f"xchg{cas_stmt.bits}"),
                        args=[addr, cas_stmt.data_lo],
                        bits=cas_stmt.bits,
                        ins_addr=cas_stmt.ins_addr,
                    )

                assignment_dst = cas_stmt.expd_lo
                stmt = Assignment(cas_stmt.idx, assignment_dst, call_expr, **cas_stmt.tags)  # type:ignore
                return [stmt]

        if next_stmt.ins_addr <= cas_stmt.ins_addr:
            # avoid matching against statements prematurely
            return None

        if cas_stmt.old_hi is None:
            # TODO: Support cases where cas_stmt.old_hi is not None
            # Case 2
            call_expr = Call(
                cas_stmt.idx,
                self._get_instrincs_name(f"cmpxchg{cas_stmt.bits}"),
                args=[
                    cas_stmt.addr,
                    cas_stmt.data_lo,
                    cas_stmt.expd_lo,
                ],
                bits=cas_stmt.bits,
                ins_addr=cas_stmt.ins_addr,
            )
            assignment_dst = cas_stmt.expd_lo
            stmt = Assignment(cas_stmt.idx, assignment_dst, call_expr, **cas_stmt.tags)  # type:ignore
            return [stmt, next_stmt]

        return None

    def _get_instrincs_name(self, mnemonic: str) -> str:
        if mnemonic in _INTRINSICS_NAMES:
            os = (
                self.project.simos.name
                if self.project is not None and self.project.simos is not None and self.project.simos.name is not None
                else "Linux"
            )
            if os not in _INTRINSICS_NAMES[mnemonic]:
                os = "Linux"
            return _INTRINSICS_NAMES[mnemonic][os]
        return mnemonic

    @staticmethod
    def _resolve_tmp_expr(expr: Expression, block) -> Expression:
        if isinstance(expr, Tmp):
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and stmt.dst.likes(expr):
                    return stmt.src
        return expr
