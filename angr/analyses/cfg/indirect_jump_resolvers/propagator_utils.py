import claripy


class PropagatorLoadCallback:
    """
    Implement the load callback for Propagator that should be used across all jump table resolvers.
    """

    def __init__(self, project):
        self.project = project

    def propagator_load_callback(self, addr, size) -> bool:  # pylint:disable=unused-argument
        # only allow loading if the address falls into a read-only region
        if isinstance(addr, claripy.ast.BV) and addr.op == "BVV":
            addr_v = addr.args[0]
        elif isinstance(addr, int):
            addr_v = addr
        else:
            return False
        section = self.project.loader.find_section_containing(addr_v)
        if section is not None:
            return section.is_readable and not section.is_writable
        segment = self.project.loader.find_segment_containing(addr_v)
        if segment is not None:
            return segment.is_readable and not segment.is_writable
        return False
