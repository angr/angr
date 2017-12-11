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


class PluginsPreset(object):

    def __init__(self):
        super(PluginsPreset, self).__init__()

    def apply_preset(self, kb):
        raise NotImplementedError


class DefaultPluginsPreset(PluginsPreset):

    def apply_preset(self, kb):
        kb.register_plugin('labels', LabelsPlugin())
        kb.register_plugin('blocks', BasicBlocksPlugin())
        kb.register_plugin('ijumps', IndirectJumpsPlugin())
        kb.register_plugin('funcs', FunctionsPlugin())


class CompatPluginsPreset(PluginsPreset):

    def apply_preset(self, kb):
        kb.register_plugin('functions', FunctionManager(kb))
        kb.register_plugin('variables', VariableManager(kb))
        kb.register_plugin('labels', LabelsPlugin())
        kb.register_plugin('data', Data(kb))
        kb.register_plugin('comments', Comments(kb))
        kb.register_plugin('resolved_indirect_jumps', set())
        kb.register_plugin('unresolved_indirect_jumps', set())


PLUGIN_PRESET = {
    'compat': CompatPluginsPreset(),
    'default': DefaultPluginsPreset(),
}
