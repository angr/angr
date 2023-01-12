from typing import Optional

from ...state_plugins.sim_action import SimActionData, SimActionObject
from ... import sim_options as o
from . import MemoryMixin


class ActionsMixinHigh(MemoryMixin):
    def load(self, addr, size=None, condition=None, fallback=None, disable_actions=False, action=None, **kwargs):
        if not disable_actions and o.AUTO_REFS in self.state.options and action is None:
            action = self.__make_action("read", addr, size, None, condition, fallback)

        r = super().load(addr, size=size, condition=condition, fallback=fallback, action=action, **kwargs)

        if not disable_actions:
            if o.AST_DEPS in self.state.options and self.category == "reg":
                r = SimActionObject(r, reg_deps=frozenset((addr,)))

            if action is not None and action.actual_addrs and o.AUTO_REFS in self.state.options:
                # ActionsMixinLow fills up action.actual_addrs. If the load fails, actual_addrs will be None or empty.
                # In that case, we do not add the action.
                action.data = action._make_object(r)
                if action.size is None:
                    action.size = len(r)

                self.state.history.add_action(action)

        return r

    def store(self, addr, data, size=None, disable_actions=False, action=None, condition=None, **kwargs):
        if not disable_actions and o.AUTO_REFS in self.state.options and action is None:
            action = self.__make_action("write", addr, size, data, condition, None)

        super().store(addr, data, size=size, action=action, condition=condition, **kwargs)

        if action is not None and not disable_actions and action.actual_addrs and o.AUTO_REFS in self.state.options:
            # ActionsMixinLow fills up action.actual_addrs. If the store fails, actual_addrs will be None or empty.
            # In that case, we do not add the action.
            self.state.history.add_action(action)

    def __make_action(self, kind, addr, size, data, condition, fallback):
        ref_size = size * self.state.arch.byte_width if size is not None else len(data) if data is not None else None
        region_type = self.category if self.category != "file" else self.id
        action = SimActionData(
            self.state, region_type, kind, addr=addr, data=data, size=ref_size, condition=condition, fallback=fallback
        )

        action.added_constraints = self.state.solver.true
        return action

    def _add_constraints(self, c, action=None, **kwargs):
        if action is not None:
            action.added_constraints = self.state.solver.And(action.added_constraints, c)
        return super()._add_constraints(c, action=action, **kwargs)


class ActionsMixinLow(MemoryMixin):
    def load(self, addr, action=None, **kwargs):
        if action is not None:
            if action.actual_addrs is None:
                action.actual_addrs = []
            action.actual_addrs.append(addr)
        return super().load(addr, action=action, **kwargs)

    def store(self, addr, data, action: Optional[SimActionData] = None, **kwargs):
        if action is not None:
            if action.actual_addrs is None:
                action.actual_addrs = []
            action.actual_addrs.append(addr)
            action.actual_value = action._make_object(data)
        return super().store(addr, data, action=action, **kwargs)
