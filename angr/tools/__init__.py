# Foundation classes
from .tool import Tool, ToolHub, ToolSet

# Default tools
from .factory import AngrObjectFactory
from .fastmem import FastMemory

default_tools = ToolSet()
default_tools.add_default_plugin('factory', AngrObjectFactory)
default_tools.add_default_plugin('fastmem', FastMemory)
ToolHub.register_preset('default', default_tools)
