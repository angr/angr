from __future__ import annotations

from .functions import FunctionManager, Function
from .variables import VariableManager
from .debug_variables import DebugVariableManager
from .comments import Comments
from .data import Data
from .indirect_jumps import IndirectJumps
from .labels import Labels
from .cfg import CFGManager
from .xrefs import XRefManager
from .plugin import KnowledgeBasePlugin
from .patches import PatchManager
from .key_definitions import KeyDefinitionManager
from .propagations import PropagationManager
from .structured_code import StructuredCodeManager
from .types import TypesStore
from .callsite_prototypes import CallsitePrototypes
from .custom_strings import CustomStrings
from .obfuscations import Obfuscations


__all__ = (
    "CFGManager",
    "CallsitePrototypes",
    "Comments",
    "CustomStrings",
    "Data",
    "DebugVariableManager",
    "Function",
    "FunctionManager",
    "IndirectJumps",
    "KeyDefinitionManager",
    "KnowledgeBasePlugin",
    "Labels",
    "Obfuscations",
    "PatchManager",
    "PropagationManager",
    "StructuredCodeManager",
    "TypesStore",
    "VariableManager",
    "XRefManager",
)
