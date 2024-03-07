import logging

import archinfo
import pyvex

from ....blade import Blade
from ....utils.constants import DEFAULT_STATEMENT
from .resolver import IndirectJumpResolver

_l = logging.getLogger(name=__name__)


class ArmElfFastResolver(IndirectJumpResolver):
    """
    Resolves indirect jumps in ARM ELF binaries
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(self.project.arch, archinfo.ArchARM):
            return False
        if jumpkind not in ("Ijk_Boring", "Ijk_Call"):
            return False
        return True

    def _resolve_default(self, stmt, block, source, cfg, blade):
        """
        Resolves the indirect jump in ARM ELF binaries where all internal function calls are performed in the following
        manner::

        ldr r3, [pc+#0x124]  ; load a constant from the constant_pool
        blx r3
        """

        if not isinstance(stmt.data, pyvex.IRExpr.Load):
            return False, []
        if not isinstance(stmt.data.addr, pyvex.IRExpr.Const):
            return False, []
        load_addr = stmt.data.addr.con.value
        load_size = stmt.data.result_size(block.tyenv) // 8
        endness = archinfo.Endness.BE if stmt.data.endness == "Iend_BE" else archinfo.Endness.LE

        # the next statement should be the default exit
        next_target = next(iter(blade.slice.successors(source)))

        if not (next_target[0] == block.addr and next_target[1] == DEFAULT_STATEMENT):
            return False, []
        next_tmp = block.next
        if next_tmp.tmp != stmt.tmp:
            return False, []

        # load the address to jump to
        try:
            target_addr = self.project.loader.memory.unpack_word(load_addr, size=load_size, endness=endness)
            if cfg.tag == "CFGFast":
                cfg._seg_list.occupy(load_addr, load_size, "pointer-array")
        except KeyError:
            return False, []

        return True, [target_addr]

    def _resolve_put(self, stmt, block, source, cfg, blade):
        """
        Resolves the indirect jump in ARM ELF binaries where all internal function calls are performed in the following
        manner::

        add     ip, pc, #0x100000
        add     ip, ip, #0x1e000
        ldr     pc, [ip,#0x884]!
        """

        # Get the value of r12 register
        if not isinstance(stmt.data, pyvex.IRExpr.Const):
            return False, []
        if not self.project.arch.register_names[stmt.offset] == "r12":
            return False, []
        load_addr = stmt.data.con.value
        load_size = stmt.data.result_size(block.tyenv) // 8
        endness = self.project.arch.default_endness

        count = 0
        for next_stmt in block.statements:
            if (
                isinstance(next_stmt, pyvex.IRStmt.WrTmp)
                and isinstance(next_stmt.data, pyvex.IRExpr.Binop)
                and "Add" in next_stmt.data.op
            ):
                load_addr += next_stmt.constants[0].value
                count += 1

        if count != 2:
            return False, []

        next_target = next(iter(blade.slice.successors(source)))

        if not next_target[0] == block.addr:
            return False, []

        # load the address to jump to
        try:
            target_addr = self.project.loader.memory.unpack_word(load_addr, size=load_size, endness=endness)
            if cfg.tag == "CFGFast":
                cfg._seg_list.occupy(load_addr, load_size, "pointer-array")
        except KeyError:
            return False, []

        return True, [target_addr]

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):
        """
        The main resolving function.

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
        sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]
        if not sources:
            return False, []

        if len(sources) != 1:
            return False, []

        source = sources[0]
        block_addr, stmt_idx = source

        if block_addr != block.addr:
            # TODO: We should be able to support this case very easily
            # TODO: Fix it when we see such a case
            return False, []

        stmt = block.statements[stmt_idx]
        if isinstance(stmt, pyvex.IRStmt.WrTmp):
            return self._resolve_default(stmt, block, source, cfg, b)
        elif isinstance(stmt, pyvex.IRStmt.Put):
            return self._resolve_put(stmt, block, source, cfg, b)
        else:
            return False, []
