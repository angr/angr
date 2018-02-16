
import logging

from pysoot.sootir.soot_statement import IfStmt, InvokeStmt, GotoStmt, AssignStmt
from pysoot.sootir.soot_expr import SootInterfaceInvokeExpr, SootSpecialInvokeExpr, SootStaticInvokeExpr, \
    SootVirtualInvokeExpr, SootInvokeExpr, SootDynamicInvokeExpr
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor

from .. import register_analysis
from ...errors import AngrCFGError, SimMemoryError, SimEngineError
from ...codenode import HookNode, SootBlockNode
from .cfg_fast import CFGFast, CFGJob
from .cfg_node import CFGNode

l = logging.getLogger('angr.analyses.cfg_fast_soot')


class CFGFastSoot(CFGFast):
    def __init__(self, **kwargs):

        if self.project.arch.name != 'Soot':
            raise AngrCFGError('CFGFastSoot only supports analyzing Soot programs.')

        super(CFGFastSoot, self).__init__(**kwargs)

        self._total_methods = None

    def _initialize_regions(self, exclude_sparse_regions, skip_specific_regions, force_segment, base_state,
                           initial_regions=None):
        # Don't do anything
        return

    def _pre_analysis(self):

        self._pre_analysis_common()

        entry = self.project.entry  # type:SootAddressDescriptor
        entry_func = entry.method

        obj = self.project.loader.main_object

        if entry_func is not None:
            method_inst = next(obj.get_method(entry_func.name, cls_name=entry_func.class_name))
        else:
            l.warning('The entry method is unknown. Try to find a main method.')
            method_inst = next(obj.main_methods, None)
            if method_inst is not None:
                entry_func = SootMethodDescriptor(method_inst.class_name, method_inst.name, method_inst.params)
            else:
                l.warning('Cannot find any main methods. Start from the first method of the first class.')
                for cls in obj.classes.values():
                    method_inst = next(iter(cls.methods), None)
                    if method_inst is not None:
                        break
                if method_inst is not None:
                    entry_func = SootMethodDescriptor(method_inst.class_name, method_inst.name,
                                                      method_inst.params)
                else:
                    raise AngrCFGError('There is no method in the Jar file.')

        # project.entry is a method
        # we should get the first block
        if method_inst.blocks:
            block_idx = method_inst.blocks[0].idx
            self._insert_job(CFGJob(SootAddressDescriptor(entry_func, block_idx, 0), entry_func, 'Ijk_Boring'))

        total_methods = 0

        # add all other methods as well
        for cls in self.project.loader.main_object.classes.values():
            for method in cls.methods:
                total_methods += 1
                if method.blocks:
                    method_des = SootMethodDescriptor(cls.name, method.name, method.params)
                    block_idx = method.blocks[0].label
                    self._insert_job(CFGJob(SootAddressDescriptor(method_des, block_idx, 0), method_des, 'Ijk_Boring'))

        self._total_methods = total_methods

    def _pre_job_handling(self, job):

        if self._show_progressbar or self._progress_callback:
            if self._total_methods:
                percentage = len(self.functions) * 100.0 / self._total_methods
                self._update_progress(percentage)

    def normalize(self):
        # The Shimple CFG is already normalized.
        pass

    def _pop_pending_job(self):

        # We are assuming all functions must return
        # TODO: Keep a map of library functions that do not return.

        if self._pending_jobs:
            return self._pending_jobs.pop(0)
        return None

    def _generate_cfgnode(self, addr, current_function_addr):
        try:

            if addr in self._nodes:
                cfg_node = self._nodes[addr]
                soot_block = cfg_node.soot_block
            else:
                soot_block = self.project.factory.block(addr).soot

                soot_block_size = self._soot_block_size(soot_block, addr.stmt_idx)

                cfg_node = CFGNode(addr, soot_block_size, self,
                                   function_address=current_function_addr, block_id=addr,
                                   soot_block=soot_block
                                   )
            return addr, current_function_addr, cfg_node, soot_block

        except (SimMemoryError, SimEngineError):
            return None, None, None, None

    def _block_get_successors(self, addr, function_addr, block, cfg_node):

        if block is None:
            # this block is not included in the artifacts...
            return [ ]

        return self._soot_get_successors(addr, function_addr, block, cfg_node)

    def _soot_get_successors(self, addr, function_id, block, cfg_node):

        # soot method
        method = next(self.project.loader.main_object.get_method(function_id))

        block_id = block.idx

        if addr.stmt_idx is None:
            addr = SootAddressDescriptor(addr.method, block_id, 0)

        successors = [ ]

        has_default_exit = True

        next_stmt_id = block.label + len(block.statements)
        last_stmt_id = method.blocks[-1].label + len(method.blocks[-1].statements) - 1

        if next_stmt_id >= last_stmt_id:
            # there should not be a default exit going to the next block
            has_default_exit = False

        # scan through block statements, looking for those that generate new exits
        for stmt in block.statements[addr.stmt_idx - block.label : ]:
            if isinstance(stmt, IfStmt):
                succ = (stmt.label, addr,
                        SootAddressDescriptor(function_id, method.block_by_label[stmt.target].idx, stmt.target),
                        'Ijk_Boring'
                        )
                successors.append(succ)

            elif isinstance(stmt, InvokeStmt):
                invoke_expr = stmt.invoke_expr

                succ = self._soot_create_invoke_successor(stmt, addr, invoke_expr)
                if succ is not None:
                    successors.append(succ)
                    has_default_exit = False
                    break

            elif isinstance(stmt, GotoStmt):
                target = stmt.target
                succ = (stmt.label, addr, SootAddressDescriptor(function_id, method.block_by_label[target].idx, target),
                        'Ijk_Boring')
                successors.append(succ)

                # blocks ending with a GoTo should not have a default exit
                has_default_exit = False
                break

            elif isinstance(stmt, AssignStmt):

                expr = stmt.right_op

                if isinstance(expr, SootInvokeExpr):
                    succ = self._soot_create_invoke_successor(stmt, addr, expr)
                    if succ is not None:
                        successors.append(succ)
                        has_default_exit = False
                        break


        if has_default_exit:
            successors.append(('default', addr,
                               SootAddressDescriptor(function_id, method.block_by_label[next_stmt_id].idx, next_stmt_id),
                               'Ijk_Boring'
                               )
                              )

        return successors

    def _soot_create_invoke_successor(self, stmt, addr, invoke_expr):

        method_class = invoke_expr.class_name
        method_name = invoke_expr.method_name
        method_params = invoke_expr.method_params
        method_desc = SootMethodDescriptor(method_class, method_name, method_params)

        if isinstance(invoke_expr, SootInterfaceInvokeExpr):
            successor = (stmt.label, addr, SootAddressDescriptor(method_desc, 0, 0), 'Ijk_Call')
        elif isinstance(invoke_expr, SootStaticInvokeExpr):
            successor = (stmt.label, addr, SootAddressDescriptor(method_desc, 0, 0), 'Ijk_Call')
        elif isinstance(invoke_expr, SootVirtualInvokeExpr):
            successor = (stmt.label, addr, SootAddressDescriptor(method_desc, 0, 0), 'Ijk_Call')
        elif isinstance(invoke_expr, SootSpecialInvokeExpr):
            successor = (stmt.label, addr, SootAddressDescriptor(method_desc, 0, 0), 'Ijk_Call')
        elif isinstance(invoke_expr, SootDynamicInvokeExpr):
            # TODO:
            successor = None
        else:
            raise Exception("WTF")

        return successor

    def _create_entries_filter_target(self, target):
        """

        :param target:
        :return:
        """

        return target

    def _loc_to_funcloc(self, location):

        if isinstance(location, SootAddressDescriptor):
            return location.method
        return location

    def _get_plt_stubs(self, functions):

        return set()

    def _to_snippet(self, cfg_node=None, addr=None, size=None, thumb=False, jumpkind=None, base_state=None):

        assert thumb is False

        if cfg_node is not None:
            addr = cfg_node.addr
            stmts_count = cfg_node.size
        else:
            addr = addr
            stmts_count = size

        if addr is None:
            raise ValueError('_to_snippet(): Either cfg_node or addr must be provided.')

        if self.project.is_hooked(addr) and jumpkind != 'Ijk_NoHook':
            hooker = self.project._sim_procedures[addr]
            size = hooker.kwargs.get('length', 0)
            return HookNode(addr, size, type(hooker))

        if cfg_node is not None:
            soot_block = cfg_node.soot_block
        else:
            soot_block = self.project.factory.block(addr).soot

        if soot_block is not None:
            stmts = soot_block.statements
            if stmts_count is None:
                stmts_count = self._soot_block_size(soot_block, addr.stmt_idx)
            stmts = stmts[addr.stmt_idx - soot_block.label : addr.stmt_idx - soot_block.label + stmts_count]
        else:
            stmts = None
            stmts_count = 0

        return SootBlockNode(addr, stmts_count, stmts)

    def _soot_block_size(self, soot_block, start_stmt_idx):

        if soot_block is None:
            return 0

        stmts_count = 0

        for stmt in soot_block.statements[start_stmt_idx - soot_block.label : ]:
            stmts_count += 1
            if isinstance(stmt, (InvokeStmt, GotoStmt)):
                break
            if isinstance(stmt, AssignStmt) and isinstance(stmt.right_op, SootInvokeExpr):
                break

        return stmts_count


register_analysis(CFGFastSoot, 'CFGFastSoot')
