from typing import Union, Optional, TYPE_CHECKING

import claripy

if TYPE_CHECKING:
    from .expression import Expression


def get_bits(expr: Union[claripy.ast.Bits,'Expression',int]) -> Optional[int]:
    # delayed import
    from .expression import Expression

    if isinstance(expr, Expression):
        return expr.bits
    elif isinstance(expr, claripy.ast.Bits):
        return expr.size()
    elif hasattr(expr, 'bits'):
        return expr.bits
    else:
        return None
