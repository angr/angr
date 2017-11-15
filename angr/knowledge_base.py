"""Representing the artifacts of a project."""

from .knowledge_plugins.plugin import default_plugins


class KnowledgeBase(object):
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    def __init__(self, project, obj):
        self._project = project
        self.obj = obj
        self._plugins = {}

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
        self._project = state['project']
        self.obj = state['obj']
        self._plugins = state['plugins']

    def __getstate__(self):
        s = {
            'project': self._project,
            'obj': self.obj,
            'plugins': self._plugins,
        }
        return s

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
