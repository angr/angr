import logging

import archinfo
import pyvex

from ....blade import Blade
from ....utils.constants import DEFAULT_STATEMENT
from .resolver import IndirectJumpResolver

_l = logging.getLogger(name=__name__)


class ArmElfFastResolver(IndirectJumpResolver):
    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(self.project.arch, archinfo.ArchARM):
            return False
        if jumpkind not in ('Ijk_Boring', 'Ijk_Call'):
            return False
        return True

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        """
        Resolves the indirect jump in ARM ELF binaries where all internal function calls are performed in the following
        manner:

        ldr r3, [pc+#0x124]  ; load a constant from the constant_pool
        blx r3

        :param cfg:             A CFG instance.
        :param int addr:        Address of the IRSB.
        :param int func_addr:   Address of the function.
        :param block:           The IRSB.
        :param str jumpkind:    The jumpkind.
        :return:
        :rtype:                 tuple
        """

        # Note that this function assumes the IRSB is optimized (opt_level > 0)
        # the logic will be vastly different if the IRSB is not optimized (opt_level == 0)

        b = Blade(cfg.graph, addr, -1, cfg=cfg, project=self.project, ignore_sp=True, ignore_bp=True, max_level=2)
        sources = [ n for n in b.slice.nodes() if b.slice.in_degree(n) == 0 ]
        if not sources:
            return False, [ ]

        if len(sources) != 1:
            return False, [ ]

        source = sources[0]
        block_addr, stmt_idx = source

        if block_addr != block.addr:
            # TODO: We should be able to support this case very easily
            # TODO: Fix it when we see such a case
            return False, [ ]

        stmt = block.statements[stmt_idx]
        if not isinstance(stmt, pyvex.IRStmt.WrTmp):
            return False, [ ]
        if not isinstance(stmt.data, pyvex.IRExpr.Load):
            return False, [ ]
        if not isinstance(stmt.data.addr, pyvex.IRExpr.Const):
            return False, [ ]
        load_addr = stmt.data.addr.con.value
        load_size = stmt.data.result_size(block.tyenv) // 8
        endness = archinfo.Endness.BE if stmt.data.endness == 'Iend_BE' else archinfo.Endness.LE

        # the next statement should be the default exit
        next_target = next(iter(b.slice.successors(source)))

        if not (next_target[0] == block.addr and next_target[1] == DEFAULT_STATEMENT):
            return False, [ ]
        next_tmp = block.next
        if next_tmp.tmp != stmt.tmp:
            return False, [ ]

        # load the address to jump to
        try:
            target_addr = self.project.loader.memory.unpack_word(load_addr, size=load_size, endness=endness)
            if cfg.tag == "CFGFast":
                cfg._seg_list.occupy(load_addr, load_size, "pointer-array")
        except KeyError:
            return False, [ ]

        return True, [ target_addr ]
