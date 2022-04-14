
import logging
l = logging.getLogger(name=__name__)

from .plugin import SimStatePlugin
from ..errors import SimUCManagerAllocationError

class SimUCManager(SimStatePlugin):
    def __init__(self, man=None):

        SimStatePlugin.__init__(self)

        if man:
            self._region_base = man._region_base
            self._pos = man._pos
            self._alloc_depth_map = man._alloc_depth_map.copy()

        else:
            self._region_base = None # It will be set later when self.state is set
            self._pos = 0

            self._alloc_depth_map = { }

        #
        # Some constants
        #

        # The size of each region, in bytes
        self._region_size = 0x1000
        # The maximum allocation depth
        self._max_alloc_depth = 20

    def assign(self, dst_addr_ast):
        """
        Assign a new region for under-constrained symbolic execution.

        :param dst_addr_ast: the symbolic AST which address of the new allocated region will be assigned to.
        :return: as ast of memory address that points to a new region
        """

        if dst_addr_ast.uc_alloc_depth > self._max_alloc_depth:
            raise SimUCManagerAllocationError('Current allocation depth %d is greater than the cap (%d)' % \
                (dst_addr_ast.uc_alloc_depth, self._max_alloc_depth))

        abs_addr = self._region_base + self._pos
        ptr = self.state.solver.BVV(abs_addr, self.state.arch.bits)
        self._pos += self._region_size

        self._alloc_depth_map[(abs_addr - self._region_base) // self._region_size] = dst_addr_ast.uc_alloc_depth

        l.debug("Assigned new memory region %s", ptr)
        return ptr

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        return SimUCManager(man=self)

    def get_alloc_depth(self, addr):
        block_pos = (addr - self._region_base) // self._region_size

        if block_pos not in self._alloc_depth_map:
            return None

        return self._alloc_depth_map[block_pos]

    def is_bounded(self, ast):
        """
        Test whether an AST is bounded by any existing constraint in the related solver.

        :param ast: an claripy.AST object
        :return: True if there is at least one related constraint, False otherwise
        """

        return len(ast.variables.intersection(self.state.solver._solver.variables)) != 0

    def set_state(self, state):
        super(SimUCManager, self).set_state(state)
        self._region_base = 0xd0 << (self.state.arch.bits - 8)


from angr.sim_state import SimState
SimState.register_default('uc_manager', SimUCManager)
