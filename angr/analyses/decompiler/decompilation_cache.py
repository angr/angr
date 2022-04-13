from typing import Optional, Set, Dict, TYPE_CHECKING

from .clinic import Clinic
from .structured_codegen import BaseStructuredCodeGenerator


class DecompilationCache:
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    __slots__ = ('addr', 'type_constraints', 'var_to_typevar', 'codegen', 'clinic', )

    def __init__(self, addr):
        self.addr = addr
        self.type_constraints: Optional[Set] = None
        self.var_to_typevar: Optional[Dict] = None
        self.codegen: Optional[BaseStructuredCodeGenerator] = None
        self.clinic: Optional[Clinic] = None

    @property
    def local_types(self):
        return self.clinic.variable_kb.variables[self.addr].types
