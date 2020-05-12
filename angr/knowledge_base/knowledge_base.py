"""Representing the artifacts of a project."""

from itertools import count
import logging

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..project import Project
    from ..knowledge_plugins import FunctionManager
    from ..knowledge_plugins import VariableManager
    from ..knowledge_plugins import KeyDefinitionManager
    from ..knowledge_plugins import CFGManager

from ..knowledge_plugins.plugin import default_plugins


l = logging.getLogger(name=__name__)


kb_ctr = count(0, 1)


class KnowledgeBase:
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    functions: 'FunctionManager'
    variables: 'VariableManager'
    defs: 'KeyDefinitionManager'
    cfgs: 'CFGManager'
    _project: 'Project'

    def __init__(self, project, obj=None, name=None):
        if obj is not None:
            l.warning("The obj parameter in KnowledgeBase.__init__() has been deprecated.")
        object.__setattr__(self, '_project', project)
        object.__setattr__(self, '_plugins', {})

        self.name = name if name else ("kb_%d" % next(kb_ctr))

    @property
    def callgraph(self):
        return self.functions.callgraph

    @property
    def unresolved_indirect_jumps(self):
        return self.indirect_jumps.unresolved

    @property
    def resolved_indirect_jumps(self):
        return self.indirect_jumps.resolved

    def __setstate__(self, state):
        object.__setattr__(self, '_project', state['project'])
        object.__setattr__(self, '_plugins', state['plugins'])

    def __getstate__(self):
        s = {
            'project': self._project,
            'plugins': self._plugins,
        }
        return s

    def __dir__(self):
        x = list(super(KnowledgeBase, self).__dir__())
        x.extend(default_plugins.keys())
        return x

    #
    # Plugin accessor
    #

    def __contains__(self, plugin_name):
        return plugin_name in self._plugins

    def __getattr__(self, v):
        try:
            return self.get_plugin(v)
        except KeyError:
            raise AttributeError(v)

    def __setattr__(self, k, v):
        self.register_plugin(k, v)

    #
    # Plugins
    #

    def has_plugin(self, name):
        return name in self._plugins

    def get_plugin(self, name):
        if name not in self._plugins:
            p = default_plugins[name](self)
            self.register_plugin(name, p)
            return p
        return self._plugins[name]

    def register_plugin(self, name, plugin):
        self._plugins[name] = plugin
        return plugin

    def release_plugin(self, name):
        if name in self._plugins:
            del self._plugins[name]
