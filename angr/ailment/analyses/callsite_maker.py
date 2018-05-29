
import logging

from angr import Analysis, register_analysis
from angr.analyses.reaching_definitions import OP_BEFORE
from angr.calling_conventions import SimRegArg, SimStackArg

from .. import Stmt, Expr

l = logging.getLogger('ailment.callsite_maker')


class CallSiteMaker(Analysis):
    """
    Add calling convention, declaration, and args to a call site.
    """
    def __init__(self, block):
        self.block = block

        self._reaching_definitions = None

        self.result_block = None

        self._analyze()

    def _analyze(self):

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

        if func.prototype is None:
            # cannot find a declaration to it
            return

        # Make arguments
        args = [ ]
        if func.calling_convention is None:
            l.warning('%s has an unknown calling convention.', repr(func))
        else:
            arg_locs = func.calling_convention.arg_locs()
            for arg_loc in arg_locs:
                if type(arg_loc) is SimRegArg:
                    size = arg_loc.size
                    offset = arg_loc._fix_offset(None, size, arch=self.project.arch)
                    args.append(Expr.Register(None, None, offset, size * 8, reg_name=arg_loc.reg_name))
                else:
                    raise NotImplementedError('Not implemented yet.')

        new_stmts = self.block.statements[::]

        new_stmts[-1] = Stmt.Call(last_stmt, last_stmt.target,
                                  calling_convention=func.calling_convention,
                                  prototype=func.prototype,
                                  args=args,
                                  **last_stmt.tags
                                  )

        new_block = self.block.copy()
        new_block.statements = new_stmts

        self.result_block = new_block

    def _get_call_target(self, stmt):
        """

        :param Stmt.Call stmt:
        :return:
        """

        if type(stmt.target) is Expr.Const:
            return stmt.target.value

        return None

register_analysis(CallSiteMaker, 'AILCallSiteMaker')
