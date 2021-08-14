from typing import Optional, Set, Dict, TYPE_CHECKING

from .structured_codegen import BaseStructuredCodeGenerator


class DecompilationCache:
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """
    def __init__(self):
        self.type_constraints: Optional[Set] = None
        self.var_to_typevar: Optional[Dict] = None
        self.codegen: Optional[BaseStructuredCodeGenerator] = None
