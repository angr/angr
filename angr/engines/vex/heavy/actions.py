from __future__ import annotations

import pyvex

from angr import sim_options as o
from angr.state_plugins.sim_action import SimActionData, SimActionExit, SimActionObject, SimActionOperation

from .heavy import HeavyVEXMixin


class TrackActionsMixin(HeavyVEXMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__tmp_deps = {}

    def _optimize_guarded_addr(self, addr, guard):
        addr, addr_deps = addr
        guard, _ = guard
        addr = super()._optimize_guarded_addr(addr, guard)
        return addr, addr_deps

    def handle_vex_block(self, irsb):
        self.__tmp_deps = {}
        super().handle_vex_block(irsb)

    def _handle_vex_const(self, const):
        return super()._handle_vex_const(const), frozenset()

    def _handle_vex_expr_GSPTR(self, expr):
        return super()._handle_vex_expr_GSPTR(expr), frozenset()

    def _handle_vex_expr_VECRET(self, expr):
        return super()._handle_vex_expr_VECRET(expr), frozenset()

    def _handle_vex_expr_Binder(self, expr):
        return super()._handle_vex_expr_Binder(expr), frozenset()

    def _instrument_vex_expr(self, result):
        return super()._instrument_vex_expr(result[0]), result[1]

    def _perform_vex_expr_Op(self, op, args):
        exprs, deps = zip(*args)
        result = super()._perform_vex_expr_Op(op, exprs)

        if o.TRACK_OP_ACTIONS in self.state.options:
            action_objects = [SimActionObject(arg, deps=dep, state=self.state) for arg, dep in args]
            r = SimActionOperation(self.state, op, action_objects, result)
            self.state.history.add_action(r)
            result_deps = frozenset((r,))
        else:
            result_deps = frozenset().union(*deps)
        return result, result_deps

    def _perform_vex_expr_ITE(self, *args):
        exprs, deps = zip(*args)
        combined_deps = frozenset().union(*deps)
        result = super()._perform_vex_expr_ITE(*exprs)
        return result, combined_deps

    # TODO for this and below: what if we made AUTO_DEPS work here?
    def _perform_vex_expr_CCall(self, func_name, ty, args, func=None):
        exprs, deps = zip(*args)
        combined_deps = frozenset().union(*deps)
        result = super()._perform_vex_expr_CCall(func_name, ty, exprs, func=None)
        return result, combined_deps

    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=None):
        exprs, deps = zip(*args) if args else ((), ())
        combined_deps = frozenset().union(*deps)
        result = super()._perform_vex_stmt_Dirty_call(func_name, ty, exprs, func=None)
        return result, combined_deps

    def _perform_vex_expr_RdTmp(self, tmp):
        result = super()._perform_vex_expr_RdTmp(tmp)

        # finish it and save the tmp reference
        if o.TRACK_TMP_ACTIONS in self.state.options:
            r = SimActionData(
                self.state,
                SimActionData.TMP,
                SimActionData.READ,
                tmp=tmp,
                size=self.irsb.tyenv.sizeof(tmp),
                data=result,
            )
            self.state.history.add_action(r)
            a = frozenset((r,))
        else:
            a = self.__tmp_deps.get(tmp, frozenset())
        return result, a

    def _perform_vex_expr_Get(self, offset, ty, **kwargs):
        offset, offset_deps = offset
        result = super()._perform_vex_expr_Get(offset, ty, **kwargs)

        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            offset_ao = SimActionObject(offset, deps=offset_deps, state=self.state)
            r = SimActionData(
                self.state,
                self.state.registers.id,
                SimActionData.READ,
                addr=offset_ao,
                size=pyvex.get_type_size(ty),
                data=result,
            )
            self.state.history.add_action(r)
            a = frozenset((r,))
        else:
            a = frozenset()
        return result, a

    def _perform_vex_expr_Load(self, addr, ty, endness, condition=None, **kwargs):
        addr, addr_deps = addr

        if condition is not None:
            condition, condition_deps = condition
        else:
            condition_deps = None

        result = super()._perform_vex_expr_Load(addr, ty, endness, condition=condition, **kwargs)

        if o.TRACK_MEMORY_ACTIONS in self.state.options:
            addr_ao = SimActionObject(addr, deps=addr_deps, state=self.state)
            condition_ao = (
                SimActionObject(condition, deps=condition_deps, state=self.state) if condition is not None else None
            )
            r = SimActionData(
                self.state,
                self.state.memory.id,
                SimActionData.READ,
                addr=addr_ao,
                size=pyvex.get_type_size(ty),
                data=result,
                condition=condition_ao,
            )
            self.state.history.add_action(r)
            a = frozenset((r,))
        else:
            a = frozenset()
        return result, a

    def _perform_vex_stmt_LoadG_guard_condition(self, guard):
        return super()._perform_vex_stmt_LoadG_guard_condition(guard[0]), guard[1]

    def _perform_vex_stmt_StoreG_guard_condition(self, guard):
        return super()._perform_vex_stmt_StoreG_guard_condition(guard[0]), guard[1]

    # statements

    def _perform_vex_stmt_WrTmp(self, tmp, data_bundle, **kwargs):  # pylint:disable=unused-argument
        data, data_deps = data_bundle

        if o.TRACK_TMP_ACTIONS not in self.state.options:
            self.__tmp_deps[tmp] = data_deps
        super()._perform_vex_stmt_WrTmp(tmp, data, deps=data_deps)

    def _perform_vex_stmt_Put(self, offset, data, **kwargs):
        offset, _ = offset
        data, data_deps = data
        # track the put
        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            data_ao = SimActionObject(data, deps=data_deps, state=self.state)
            size_ao = SimActionObject(len(data))
            a = SimActionData(
                self.state, SimActionData.REG, SimActionData.WRITE, addr=offset, data=data_ao, size=size_ao
            )
            self.state.history.add_action(a)
        else:
            a = None

        super()._perform_vex_stmt_Put(offset, data, action=a, **kwargs)

    def _perform_vex_stmt_Store(self, addr, data, endness, condition=None, **kwargs):
        addr, addr_deps = addr
        data, data_deps = data

        if condition is not None:
            condition, condition_deps = condition
        else:
            condition_deps = None

        # track the write
        if o.TRACK_MEMORY_ACTIONS in self.state.options and addr_deps is not None:
            data_ao = SimActionObject(data, deps=data_deps, state=self.state)
            addr_ao = SimActionObject(addr, deps=addr_deps, state=self.state)
            size_ao = SimActionObject(len(data))
            cond_ao = (
                SimActionObject(condition, deps=condition_deps, state=self.state)
                if condition_deps is not None
                else None
            )
            a = SimActionData(
                self.state,
                SimActionData.MEM,
                SimActionData.WRITE,
                data=data_ao,
                size=size_ao,
                addr=addr_ao,
                condition=cond_ao,
            )
            self.state.history.add_action(a)
        else:
            a = None

        super()._perform_vex_stmt_Store(addr, data, endness, action=a, condition=condition, **kwargs)

    def _perform_vex_stmt_Exit(self, guard, expr, jumpkind):
        guard, guard_deps = guard
        target, target_deps = expr

        if o.TRACK_JMP_ACTIONS in self.state.options:
            guard_ao = SimActionObject(guard, deps=guard_deps, state=self.state)
            target_ao = SimActionObject(target, deps=target_deps, state=self.state)
            self.state.history.add_action(
                SimActionExit(self.state, target=target_ao, condition=guard_ao, exit_type=SimActionExit.CONDITIONAL)
            )

        super()._perform_vex_stmt_Exit(guard, target, jumpkind)

    def _perform_vex_defaultexit(self, target_bundle, jumpkind):
        if target_bundle is not None:
            target, target_deps = target_bundle

            if o.TRACK_JMP_ACTIONS in self.state.options:
                target_ao = SimActionObject(target, deps=target_deps, state=self.state)
                self.state.history.add_action(SimActionExit(self.state, target_ao, exit_type=SimActionExit.DEFAULT))
        else:
            target = None

        super()._perform_vex_defaultexit(target, jumpkind)
