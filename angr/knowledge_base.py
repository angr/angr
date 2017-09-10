from .errors import KnowledgeBaseNoPlugin


class KnowledgeBase(object):
    """Represents a "model" of knowledge about an artifact.

    The knowledge base should contain as absolutely little redundant data
    as possible - effectively the most fundemental artifacts that we can
    use to efficiently reconstruct anything the user would want to know about.
    """
    _default_plugins = {}

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
        return self.get_plugin(v)

    #
    # Plugins
    #

    def has_plugin(self, name):
        return name in self._plugins

    def get_plugin(self, name):
        if name in self._plugins:
            return self._plugins[name]

        elif name in self._default_plugins:
            plugin_cls = self._default_plugins[name]
            return self.register_plugin(name, plugin_cls(kb=self))

        else:
            raise KnowledgeBaseNoPlugin("No such plugin: %s" % name)

    def register_plugin(self, name, plugin):
        self._plugins[name] = plugin
        return plugin

    def release_plugin(self, name):
        if name in self._plugins:
            del self._plugins[name]

    @classmethod
    def register_default(cls, name, plugin_cls):
        if name in cls._default_plugins:
            raise Exception("%s is already set as the default for %s" % (cls._default_plugins[name], name))
        cls._default_plugins[name] = plugin_cls


import knowledge_plugins
KnowledgeBase.register_default('basic_blocks', knowledge_plugins.BasicBlocksPlugin)
KnowledgeBase.register_default('comments', knowledge_plugins.Comments)
KnowledgeBase.register_default('data', knowledge_plugins.Data)
KnowledgeBase.register_default('indirect_jumps', knowledge_plugins.IndirectJumps)
KnowledgeBase.register_default('labels', knowledge_plugins.LabelsPlugin)
KnowledgeBase.register_default('functions', knowledge_plugins.FunctionManager)
KnowledgeBase.register_default('variables', knowledge_plugins.VariableManager)
