from __future__ import annotations
import logging

import claripy

from angr.engines.ail.callstack import AILCallStack
from angr.storage.memory_mixins.memory_mixin import MemoryMixin


log = logging.getLogger(__name__)


class VariableReferenceMixin(MemoryMixin):
    @property
    def frame(self) -> AILCallStack:
        callstack = self.state.callstack
        assert isinstance(callstack, AILCallStack)
        return callstack

    def load(self, addr, size=None, **kwargs):
        region, offset = self._find_ptr_region(addr)
        if region is not self:
            return region.load(offset, size, **kwargs)
        return super().load(addr, size, **kwargs)

    def store(self, addr, data, size=None, **kwargs) -> None:
        region, offset = self._find_ptr_region(addr)
        if region is not self:
            return region.store(offset, data, size, **kwargs)
        return super().store(addr, data, size, **kwargs)

    def _find_ptr_region(self, ptr: claripy.ast.BV) -> tuple[MemoryMixin, claripy.ast.BV | int]:
        region: MemoryMixin | None = None
        offset = 0
        queue = [ptr]
        while queue:
            node = queue.pop()
            if node.op == "__add__":
                queue.extend(node.args)  # type: ignore
            elif node.op == "__sub__":
                queue.append(node.args[0])  # type: ignore
                queue.extend(-x for x in node.args[1:])  # type: ignore
            elif node.op == "BVS":
                frame = self.frame
                while frame is not None:
                    referred = frame.var_refs.get(node, None)
                    if referred is None:
                        frame = frame.next
                        continue
                    if region is None:
                        _region = frame.vars[referred]
                        assert isinstance(_region, MemoryMixin)
                        region = _region
                    else:
                        log.warning("Emulation is adding together two pointers")
                        return self.state.memory, ptr
                    break
                else:
                    offset += node
            else:
                offset += node

        if region is None:
            return self.state.memory, ptr
        return region, offset
