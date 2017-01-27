
import logging

from pysoot.sootir.soot_statement import IfStmt, InvokeStmt
from pysoot.sootir.soot_expr import SootInterfaceInvokeExpr, SootSpecialInvokeExpr, SootStaticInvokeExpr, \
    SootVirtualInvokeExpr
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor

from .. import register_analysis
from ...errors import AngrCFGError, SimMemoryError, SimEngineError
from .cfg_fast import CFGFast, CFGJob
from .cfg_node import CFGNode

l = logging.getLogger('angr.analyses.cfg_fast_soot')


class CFGFastSoot(CFGFast):
    def __init__(self, **kwargs):

        if self.project.arch.name != 'Soot':
            raise AngrCFGError('CFGFastSoot only supports analyzing Soot programs.')

        super(CFGFastSoot, self).__init__(**kwargs)

    def _initialize_regions(self, exclude_sparse_regions, skip_specific_regions, force_segment, base_state,
                           initial_regions=None):
        # Don't do anything
        return

    def _pre_analysis(self):

        self._pre_analysis_common()

        entry_func = self.project.entry

        obj = self.project.loader.main_object

        if entry_func is not None:
            method_inst = obj.get_method(entry_func.name, cls_name=entry_func.class_name)[0]
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
            block_label = method_inst.blocks[0].label
            self._insert_job(CFGJob(SootAddressDescriptor(entry_func, block_label, 0), entry_func, 'Ijk_Boring'))

        # add all other methods as well
        """
        for cls in self.project.loader.main_bin.classes.values():
            for method in cls.methods:
                if method.blocks:
                    func = cls.name + "." + method.name
                    block_label = method.blocks[0].label
                    self._insert_entry(CFGJob((func, block_label), func, 'Ijk_Boring'))
        """

    def _pre_job_handling(self, job):
        pass

    def _generate_cfgnode(self, addr, current_function_addr):
        try:

            if addr in self._nodes:
                cfg_node = self._nodes[addr]
                soot_block = cfg_node.soot_block
            else:
                soot_block = self.project.factory.block(addr).soot

                cfg_node = CFGNode(addr, 0, self, function_address=current_function_addr, block_id=addr,
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

        block_id = block.label

        if addr.stmt_idx is None:
            addr = SootAddressDescriptor(addr.method, block_id, 0)

        successors = [ ]

        next_stmt_id = block_id + len(block.statements)
        last_stmt_id = method.blocks[-1].label + len(method.blocks[-1].statements) - 1

        if next_stmt_id < last_stmt_id:
            # there is a default exit going to the next block
            successors.append(('default', addr,
                               SootAddressDescriptor(function_id, block_id, next_stmt_id), 'Ijk_Boring'))

        # scan through block statements, looking for those that generate new exits
        for stmt in block.statements:
            if isinstance(stmt, IfStmt):
                succ = (stmt.label, addr, SootAddressDescriptor(function_id, stmt.target), 'Ijk_Boring')
                successors.append(succ)
            elif isinstance(stmt, InvokeStmt):
                invoke_expr = stmt.invoke_expr

                method_class = invoke_expr.class_name
                method_name = invoke_expr.method_name
                method_params = invoke_expr.method_params
                method_desc = SootMethodDescriptor(method_class, method_name, method_params)

                if isinstance(invoke_expr, SootInterfaceInvokeExpr):
                    successors.append((stmt.label, addr, SootAddressDescriptor(method_desc, None, None), 'Ijk_Call'))
                elif isinstance(invoke_expr, SootStaticInvokeExpr):
                    successors.append((stmt.label, addr, SootAddressDescriptor(method_desc, None, None), 'Ijk_Call'))
                elif isinstance(invoke_expr, SootVirtualInvokeExpr):
                    successors.append((stmt.label, addr, SootAddressDescriptor(method_desc, None, None), 'Ijk_Call'))
                elif isinstance(invoke_expr, SootSpecialInvokeExpr):
                    successors.append((stmt.label, addr, SootAddressDescriptor(method_desc, None, None), 'Ijk_Call'))
                else:
                    raise Exception("WTF")

        return successors

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


register_analysis(CFGFastSoot, 'CFGFastSoot')
