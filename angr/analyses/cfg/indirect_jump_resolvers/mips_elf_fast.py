
import logging

import pyvex
import archinfo


from .... import options, BP_BEFORE
from ....blade import Blade
from ....annocfg import AnnotatedCFG
from ....exploration_techniques import Slicecutor

from .resolver import IndirectJumpResolver


l = logging.getLogger(name=__name__)


class MipsElfFastResolver(IndirectJumpResolver):
    def __init__(self, project):
        super(MipsElfFastResolver, self).__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(self.project.arch, (archinfo.ArchMIPS32, archinfo.ArchMIPS64, )):
            return False
        return True

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        """
        Resolves the indirect jump in MIPS ELF binaries where all external function calls are indexed using gp.

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :param str jumpkind: The jumpkind.
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """

        project = self.project

        b = Blade(cfg.graph, addr, -1, cfg=cfg, project=project, ignore_sp=True, ignore_bp=True,
                  ignored_regs=('gp',)
                  )

        sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]
        if not sources:
            return False, []

        source = sources[0]
        source_addr = source[0]
        annotated_cfg = AnnotatedCFG(project, None, detect_loops=False)
        annotated_cfg.from_digraph(b.slice)

        state = project.factory.blank_state(addr=source_addr, mode="fastpath",
                                            remove_options=options.refs,
                                            # suppress unconstrained stack reads for `gp`
                                            add_options={options.SYMBOL_FILL_UNCONSTRAINED_MEMORY},
                                            )
        func = cfg.kb.functions.function(addr=func_addr)

        gp_offset = project.arch.registers['gp'][0]
        if 'gp' not in func.info:
            sec = project.loader.find_section_containing(func.addr)
            if sec is None or sec.name != '.plt':
                # this might a special case: gp is only used once in this function, and it can be initialized right before
                # its use site.
                # TODO: handle this case
                l.debug('Failed to determine value of register gp for function %#x.', func.addr)
                return False, [ ]
        else:
            state.regs.gp = func.info['gp']

        def overwrite_tmp_value(state):
            state.inspect.tmp_write_expr = state.solver.BVV(func.info['gp'], state.arch.bits)

        # Special handling for cases where `gp` is stored on the stack
        got_gp_stack_store = False
        for block_addr_in_slice in set(slice_node[0] for slice_node in b.slice.nodes()):
            for stmt in project.factory.block(block_addr_in_slice).vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == gp_offset and \
                        isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    tmp_offset = stmt.data.tmp  # pylint:disable=cell-var-from-loop
                    # we must make sure value of that temporary variable equals to the correct gp value
                    state.inspect.make_breakpoint('tmp_write', when=BP_BEFORE,
                                                  condition=lambda s, bbl_addr_=block_addr_in_slice,
                                                                   tmp_offset_=tmp_offset:
                                                  s.scratch.bbl_addr == bbl_addr_ and s.inspect.tmp_write_num == tmp_offset_,
                                                  action=overwrite_tmp_value
                                                  )
                    got_gp_stack_store = True
                    break
            if got_gp_stack_store:
                break

        simgr = self.project.factory.simulation_manager(state)
        simgr.use_technique(Slicecutor(annotated_cfg))
        simgr.run()

        if simgr.cut:
            # pick the successor that is cut right after executing `addr`
            try:
                target_state = next(iter(cut for cut in simgr.cut if cut.history.addr == addr))
            except StopIteration:
                l.debug("Indirect jump at %#x cannot be resolved by %s.", addr, repr(self))
                return False, [ ]
            target = target_state.addr

            if self._is_target_valid(cfg, target):
                l.debug("Indirect jump at %#x is resolved to target %#x.", addr, target)
                return True, [ target ]

            l.debug("Indirect jump at %#x is resolved to target %#x, which seems to be invalid.", addr, target)
            return False, [ ]

        l.debug("Indirect jump at %#x cannot be resolved by %s.", addr, repr(self))
        return False, [ ]
