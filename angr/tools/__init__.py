# Foundation classes
from .tool import Tool, ToolHub, ToolSet

default_tools = ToolSet()
ToolHub.register_preset('default', default_tools)
