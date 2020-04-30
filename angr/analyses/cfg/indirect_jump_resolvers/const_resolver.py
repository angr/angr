import logging

import pyvex

from .resolver import IndirectJumpResolver
from ...code_location import CodeLocation
from ...propagator import vex_vars

l = logging.getLogger(name=__name__)


class ConstantResolver(IndirectJumpResolver):
    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        """
        Filters out calls not supported by this resolver. Supported:
        Ijk_Boring - Indirect jumps
        Ijk_Call - Indirect Calls
        """

        # we support both an indirect call and jump since the value can be resolved
        if jumpkind in ('Ijk_Boring', 'Ijk_Call'):
            return True

        return False

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        """
        This function does the actual resolve. Our process is easy:
        Get the basic block, and find the target jump. Propagate all constants
        across the binary until we get to the block. Load constants from mem as needed.
        If jmp/call is a int, we return.
        """
        if isinstance(block.next, pyvex.expr.RdTmp):
            func = cfg.functions[func_addr]
            unoptimized_block = self.project.factory.block(addr, opt_level=0)
            propagator = self.project.analyses.Propagator(block=unoptimized_block, only_consts=True)
            replacements = propagator.replacements
            if replacements:
                block_loc = CodeLocation(unoptimized_block.addr, None)
                tmp_var = vex_vars.VEXTmp(unoptimized_block.vex.next.tmp)

                resolved_tmp = None
                try:
                    resolved_tmp = replacements[block_loc][tmp_var]
                except KeyError:
                    return False, [ ]

                if isinstance(resolved_tmp, int):
                    return True, [resolved_tmp]
        return False, [ ]
    
