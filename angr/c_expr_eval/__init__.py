from typing import TYPE_CHECKING
import logging

from antlr4 import CommonTokenStream
from antlr4.InputStream import InputStream

import claripy
import angr

from .CexprLexer import CexprLexer
from .CexprParser import CexprParser
from .c_expr_eval_visitor import C_expr_eval_visitor

l = logging.getLogger(name=__name__)


def c_expr_eval(c_expr: str, variable_lookup) -> claripy.ast.bv.BV:
    """
    Evaluate (restricted) c expression in angr. You can use variables and types (registered in angr).
    Pointer arithmetic, e.g. "*(ptr + 5)", "(int*)0x12345", is currently not supported.
    For variables loaded from debugging info use state.dvars.eval_expr().

    :param str c_expr:                  C expression to evaluate
    :param str->Any variable_lookup:    Function for variable name resolution (return should be SimMemView compatible)

    Example:
        angr.types.register_types(angr.types.parse_type('struct abcd { int x; int y; }'))
        c_expr = "myvar == ((struct abcd)mystructvar).y"
        variable_lookup = lambda varname: state.mem(p.loader.main_object.get_symbol( varname ).rebased_addr)
        translate_expr(c_expr, variable_lookup)
        # returns <Bool True>

    Warning:
        '(int)*x' is parsed as a multiplication; use '(int)(*x)' for the typecast
    """
    python_expr = c_expr_transl(c_expr)
    return eval(python_expr, {"angr": angr, "claripy": claripy, "variable_lookup": variable_lookup})


def c_expr_transl(c_expr: str) -> str:
    """
    Translate (restricted) c expression into angr python syntax. You can use variables and types (registered in angr).
    Pointer arithmetic, e.g. "*(ptr + 5)", "(int*)0x12345", is currently not supported.
    Evaluate your the resulting string with c_expr_eval().

    :param str var_res_right:   Right part of the variable name resolution
    :return str:                The resulting string to be evaluated using python's eval.

    Example:
        translate_expr("(int)global_struct->struct_pointer > *pointer2")
        # returns "claripy.UGT(variable_lookup('global_struct').member('struct_pointer').deref\
        #          .with_type(angr.types.parse_type('int')).resolved, variable_lookup('pointer2').deref.resolved)"

    Warning:
        '(int)*x' is parsed as a multiplication; use '(int)(*x)' for the typecast
    """
    input_stream = InputStream(c_expr)
    lexer = CexprLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = CexprParser(stream)
    tree = parser.expression()
    visitor = C_expr_eval_visitor()
    python_expr = visitor.visit(tree)
    return python_expr
