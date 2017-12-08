# Plugin base class
from .plugin import KnowledgeBasePlugin

# New-style plugins
from .labels import LabelsPlugin
from .blocks import BasicBlocksPlugin
from .ijumps import IndirectJumpsPlugin
from .funcs import FunctionsPlugin

# Legacy plugins
from .functions import FunctionManager, Function
from .variables import VariableManager
from .comments import Comments
from .data import Data

