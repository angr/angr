"""Representing the artifacts of a project."""

from .knowledge_plugins.plugin import default_plugins


class KnowledgeBase(object):
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    def __init__(self, project, obj):
        object.__setattr__(self, '_project', project)
        object.__setattr__(self, 'obj', obj)
        object.__setattr__(self, '_plugins', {})

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
        object.__setattr__(self, 'obj', state['obj'])
        object.__setattr__(self, '_plugins', state['plugins'])

    def __getstate__(self):
        s = {
            'project': self._project,
            'obj': self.obj,
            'plugins': self._plugins,
        }
        return s

    def __dir__(self):
        x = super(KnowledgeBase, self).__dir__()
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
