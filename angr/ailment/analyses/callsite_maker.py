
import logging

from angr import Analysis, register_analysis
from angr.sim_variable import SimStackVariable
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.analyses.reaching_definitions.constants import OP_BEFORE
from angr.analyses.reaching_definitions.definition import Definition

from .. import Stmt, Expr

l = logging.getLogger('ailment.callsite_maker')


class CallSiteMaker(Analysis):
    """
    Add calling convention, declaration, and args to a call site.
    """
    def __init__(self, block, reaching_definitions=None):
        self.block = block

        self._reaching_definitions = reaching_definitions

        self.result_block = None

        self._analyze()

    def _analyze(self):

        if not self.block.statements:
            return

        last_stmt = self.block.statements[-1]

        if not type(last_stmt) is Stmt.Call:
            self.result_block = self.block
            return

        target = self._get_call_target(last_stmt)

        if target is None:
            return

        if target not in self.kb.functions:
            return

        func = self.kb.functions[target]

        if func.prototype is None:
            func.find_declaration()

        args = [ ]

        if func.prototype is not None:
            # Make arguments
            if func.calling_convention is None:
                l.warning('%s has an unknown calling convention.', repr(func))
            else:
                arg_locs = func.calling_convention.arg_locs()
                for arg_loc in arg_locs:
                    if type(arg_loc) is SimRegArg:
                        size = arg_loc.size
                        offset = arg_loc._fix_offset(None, size, arch=self.project.arch)

                        arg_added = False
                        if self._reaching_definitions is not None:
                            # Find its definition
                            ins_addr = last_stmt.tags['ins_addr']
                            try:
                                rd = self._reaching_definitions.get_reaching_definitions_by_insn(ins_addr, OP_BEFORE)
                            except KeyError:
                                rd = None

                            if rd is not None:
                                defs = rd.register_definitions.get_variables_by_offset(offset)
                                if not defs:
                                    l.warning("Did not find any reaching definition for register %s at instruction %x.",
                                              arg_loc, ins_addr)
                                elif len(defs) > 1:
                                    l.warning("TODO: More than one reaching definition are found at instruction %x.",
                                              ins_addr)
                                else:
                                    # Find the definition
                                    def_ = next(iter(defs))  # type:Definition
                                    var_or_value = self._find_variable_from_definition(def_)
                                    if var_or_value is not None:
                                        args.append(var_or_value)
                                        arg_added = True

                        if not arg_added:
                            # Reaching definitions are not available. Create a register expression instead.
                            args.append(Expr.Register(None, None, offset, size * 8, reg_name=arg_loc.reg_name))
                    else:
                        raise NotImplementedError('Not implemented yet.')

        new_stmts = self.block.statements[:-1]

        if self.project.arch.call_pushes_ret:
            # check if the last statement is storing the return address onto the top of the stack
            if len(new_stmts) >= 1:
                the_stmt = new_stmts[-1]
                if isinstance(the_stmt, Stmt.Store) and isinstance(the_stmt.data, Expr.Const):
                    if isinstance(the_stmt.variable, SimStackVariable) and \
                            the_stmt.data.value == self.block.addr + self.block.original_size:
                        # yes it is!
                        new_stmts = new_stmts[:-1]

        new_stmts.append(Stmt.Call(last_stmt, last_stmt.target,
                                   calling_convention=func.calling_convention,
                                   prototype=func.prototype,
                                   args=args,
                                   **last_stmt.tags,
                                   ))

        new_block = self.block.copy()
        new_block.statements = new_stmts

        self.result_block = new_block

    def _find_variable_from_definition(self, def_):
        """

        :param Definition def_: The reaching definition of a variable.
        :return:                The variable that is defined.
        """

        if def_.codeloc.block_addr != self.block.addr:
            l.warning("TODO: The definition comes from a different block %#x.", def_.codeloc.block_addr)
            return None

        stmt = self.block.statements[def_.codeloc.stmt_idx]
        if type(stmt) is Stmt.Assignment:
            return stmt.dst
        elif type(stmt) is Stmt.Store:
            return stmt.addr
        else:
            l.warning("TODO: Unsupported statement type %s for definitions.", type(stmt))
            return None

    def _get_call_target(self, stmt):
        """

        :param Stmt.Call stmt:
        :return:
        """

        if type(stmt.target) is Expr.Const:
            return stmt.target.value

        return None


register_analysis(CallSiteMaker, 'AILCallSiteMaker')
