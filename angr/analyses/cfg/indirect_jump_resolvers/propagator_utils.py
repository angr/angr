from __future__ import annotations
import claripy


class PropagatorLoadCallback:
    """
    Implement the load callback for Propagator that should be used across all jump table resolvers.
    """

    def __init__(self, project):
        self.project = project

    def propagator_load_callback(self, addr: claripy.ast.BV | int, size: int) -> bool:  # pylint:disable=unused-argument
        # only allow loading if the address falls into a read-only region
        if isinstance(addr, claripy.ast.BV) and addr.op == "BVV":
            addr_v = addr.args[0]
        elif isinstance(addr, int):
            addr_v = addr
        else:
            return False
        section = self.project.loader.find_section_containing(addr_v)
        segment = None
        if section is not None:
            if section.is_readable and not section.is_writable:
                # read-only section
                return True
        else:
            segment = self.project.loader.find_segment_containing(addr_v)
            if segment is not None and segment.is_readable and not segment.is_writable:
                # read-only segment
                return True

        if (size == self.project.arch.bytes and (section is not None and section.is_readable)) or (
            segment is not None and segment.is_readable
        ):
            # memory is mapped and readable. does it contain a valid address?
            try:
                target_addr = self.project.loader.memory.unpack_word(
                    addr_v, size=size, endness=self.project.arch.memory_endness
                )
                if target_addr >= 0x1000 and self.project.loader.find_object_containing(target_addr) is not None:
                    return True
            except KeyError:
                return False

        return False
