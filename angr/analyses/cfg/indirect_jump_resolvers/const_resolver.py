import pyvex
from .resolver import IndirectJumpResolver
from ...code_location import CodeLocation
from ...propagator import vex_vars
import logging

l = logging.getLogger(name=__name__)


class ConstantResolver(IndirectJumpResolver):
    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        """
        This function acts as a filter for possible instructions.

        """

        # we support both an indirect call and jump since the value can be resolved
        if jumpkind in ('Ijk_Boring', 'Ijk_Call'):
            return True

        return False

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        """
        This function does the actual resolve. Our process is easy:

        """

        if isinstance(block.next, pyvex.expr.RdTmp):
            func = cfg.functions[func_addr]
            propagator = self.project.analyses.Propagator(func=func, only_consts=True)
            replacements = propagator.replacements

            if replacements:
                block_loc = CodeLocation(block.addr, None)
                tmp_var = vex_vars.VEXTmp(block.next.tmp)

                resolved_tmp = None
                try:
                    resolved_tmp = replacements[block_loc][tmp_var]
                except KeyError:
                    return False, [ ]

                if isinstance(resolved_tmp, int):
                    return True, [resolved_tmp]

        return False, [ ]
