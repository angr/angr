
import pycparser

from .calling_conventions import DEFAULT_CC


class Callable(object):
    """
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.

    If you set perform_merge=True (the default), the result will be returned to you, and
    you can get the result state with callable.result_state.

    Otherwise, you can get the resulting simulation manager at callable.result_path_group.
    """

    def __init__(self, project, addr, concrete_only=False, perform_merge=True, base_state=None, toc=None, cc=None):
        """
        :param project:         The project to operate on
        :param addr:            The address of the function to use

        The following parameters are optional:

        :param concrete_only:   Throw an exception if the execution splits into multiple paths
        :param perform_merge:   Merge all result states into one at the end (only relevant if concrete_only=False)
        :param base_state:      The state from which to do these runs
        :param toc:             The address of the table of contents for ppc64
        :param cc:              The SimCC to use for a calling convention
        """

        self._project = project
        self._addr = addr
        self._concrete_only = concrete_only
        self._perform_merge = perform_merge
        self._base_state = base_state
        self._toc = toc
        self._cc = cc if cc is not None else DEFAULT_CC[project.arch.name](project.arch)
        self._deadend_addr = project.simos.return_deadend

        self.result_path_group = None
        self.result_state = None

    def set_base_state(self, state):
        """
        Swap out the state you'd like to use to perform the call
        :param state: The state to use to perform the call
        """
        self._base_state = state

    def __call__(self, *args):
        self.perform_call(*args)
        if self.result_state is not None:
            return self.result_state.solver.simplify(self._cc.get_return_val(self.result_state, stack_base=self.result_state.regs.sp - self._cc.STACKARG_SP_DIFF))
        else:
            return None

    def perform_call(self, *args):
        state = self._project.factory.call_state(self._addr, *args,
                    cc=self._cc,
                    base_state=self._base_state,
                    ret_addr=self._deadend_addr,
                    toc=self._toc)

        def step_func(pg):
            pg2 = pg.prune()
            if len(pg2.active) > 1:
                raise AngrCallableMultistateError("Execution split on symbolic condition!")
            return pg2

        caller = self._project.factory.simulation_manager(state)
        caller.run(step_func=step_func if self._concrete_only else None).unstash(from_stash='deadended')
        caller.prune(filter_func=lambda pt: pt.addr == self._deadend_addr)

        if len(caller.active) == 0:
            raise AngrCallableError("No paths returned from function")

        self.result_path_group = caller.copy()

        if self._perform_merge:
            caller.merge()
            self.result_state = caller.active[0]

    def call_c(self, c_args):
        """
        Call this Callable with a string of C-style arguments.

        :param str c_args:  C-style arguments.
        :return:            The return value from the call.
        :rtype:             claripy.Ast
        """

        c_args = c_args.strip()
        if c_args[0] != "(":
            c_args = "(" + c_args
        if c_args[-1] != ")":
            c_args += ")"

        # Parse arguments
        content = "int main() { func%s; }" % c_args
        ast = pycparser.CParser().parse(content)

        if not ast.ext or not isinstance(ast.ext[0], pycparser.c_ast.FuncDef):
            raise AngrCallableError("Error in parsing the given C-style argument string.")

        if not ast.ext[0].body.block_items or not isinstance(ast.ext[0].body.block_items[0], pycparser.c_ast.FuncCall):
            raise AngrCallableError("Error in parsing the given C-style argument string: "
                                    "Cannot find the expected function call.")

        arg_exprs = ast.ext[0].body.block_items[0].args.exprs

        args = [ ]
        for expr in arg_exprs:
            if isinstance(expr, pycparser.c_ast.Constant):
                # string
                if expr.type == "string":
                    args.append(expr.value[1:-1])
                elif expr.type == "int":
                    args.append(int(expr.value))
                else:
                    raise AngrCallableError("Unsupported expression type %s." % expr.type)
            else:
                raise AngrCallableError("Unsupported expression type %s." % type(expr))

        return self.__call__(*args)


from .errors import AngrCallableError, AngrCallableMultistateError
