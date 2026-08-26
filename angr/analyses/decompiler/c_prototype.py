from __future__ import annotations

import copy
from typing import TYPE_CHECKING, overload

from angr.sim_type import SimTypeArray, SimTypeFunction, SimTypePointer

if TYPE_CHECKING:
    from archinfo import Arch


@overload
def c_function_type_with_array_return_decay(prototype: None, arch: Arch) -> None: ...


@overload
def c_function_type_with_array_return_decay(prototype: SimTypeFunction, arch: Arch) -> SimTypeFunction: ...


def c_function_type_with_array_return_decay(prototype: SimTypeFunction | None, arch: Arch) -> SimTypeFunction | None:
    """Return a C view of *prototype*, applying the mandatory outermost array-to-pointer adjustment."""
    if prototype is None:
        return None
    returnty = prototype.returnty
    if not isinstance(returnty, SimTypeArray):
        return prototype

    elem_type = copy.copy(returnty.elem_type)
    if returnty.qualifier:
        elem_type.qualifier = tuple(dict.fromkeys((*tuple(elem_type.qualifier or ()), *tuple(returnty.qualifier))))

    c_prototype = copy.copy(prototype)
    c_prototype.returnty = SimTypePointer(elem_type).with_arch(arch)
    return c_prototype
