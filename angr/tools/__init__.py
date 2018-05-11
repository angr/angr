# Foundation classes
from .tool import Tool, ToolHub, ToolSet

# Default tools
from .factory import AngrObjectFactory

default_tools = ToolSet()
default_tools.add_default_plugin('factory', AngrObjectFactory)
ToolHub.register_preset('default', default_tools)
