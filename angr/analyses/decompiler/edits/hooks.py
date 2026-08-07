from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.sim_type import SimType, SimTypeFunction
    from angr.sim_variable import SimVariable


@runtime_checkable
class EditHooks(Protocol):
    """
    Notifications fired immediately *before* each mutation, while the old value is still readable
    from the knowledge base.

    The method set mirrors angr-management's plugin hooks one-for-one so its adapter is a pure
    forwarder. Firing before the mutation matches what the GUI's own edit dialogs do, and is what
    lets a handler snapshot pre-edit state.
    """

    def before_function_renamed(self, func: Function, old_name: str, new_name: str) -> None: ...

    def before_stack_var_renamed(self, func: Function, offset: int, old_name: str, new_name: str) -> None: ...

    def before_func_arg_renamed(self, func: Function, arg_index: int, old_name: str, new_name: str) -> None: ...

    def before_global_var_renamed(self, addr: int, old_name: str, new_name: str) -> None: ...

    def before_stack_var_retyped(
        self, func: Function, offset: int, old_type: SimType | None, new_type: SimType
    ) -> None: ...

    def before_func_arg_retyped(
        self, func: Function, arg_index: int, old_type: SimType | None, new_type: SimType
    ) -> None: ...

    def before_global_var_retyped(self, addr: int, old_type: SimType | None, new_type: SimType) -> None: ...

    def before_other_var_retyped(self, var: SimVariable, old_type: SimType | None, new_type: SimType) -> None: ...

    def before_function_retyped(
        self, func: Function, old_proto: SimTypeFunction | None, new_proto: SimTypeFunction
    ) -> None: ...

    def before_comment_changed(self, addr: int, old: str, new: str, created: bool, decomp: bool) -> None: ...


class NullEditHooks:
    """A concrete no-op implementation. Subclass it so an adapter only overrides what it needs."""

    def before_function_renamed(self, func: Function, old_name: str, new_name: str) -> None:
        pass

    def before_stack_var_renamed(self, func: Function, offset: int, old_name: str, new_name: str) -> None:
        pass

    def before_func_arg_renamed(self, func: Function, arg_index: int, old_name: str, new_name: str) -> None:
        pass

    def before_global_var_renamed(self, addr: int, old_name: str, new_name: str) -> None:
        pass

    def before_stack_var_retyped(
        self, func: Function, offset: int, old_type: SimType | None, new_type: SimType
    ) -> None:
        pass

    def before_func_arg_retyped(
        self, func: Function, arg_index: int, old_type: SimType | None, new_type: SimType
    ) -> None:
        pass

    def before_global_var_retyped(self, addr: int, old_type: SimType | None, new_type: SimType) -> None:
        pass

    def before_other_var_retyped(self, var: SimVariable, old_type: SimType | None, new_type: SimType) -> None:
        pass

    def before_function_retyped(
        self, func: Function, old_proto: SimTypeFunction | None, new_proto: SimTypeFunction
    ) -> None:
        pass

    def before_comment_changed(self, addr: int, old: str, new: str, created: bool, decomp: bool) -> None:
        pass


NULL_HOOKS = NullEditHooks()


def coerce_hooks(hooks: EditHooks | None) -> EditHooks:
    return NULL_HOOKS if hooks is None else hooks
