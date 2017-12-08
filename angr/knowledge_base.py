import cle

from .errors import KnowledgeBaseNoPlugin

import logging
l = logging.getLogger(name=__name__)


class KnowledgeBase(object):
    """Represents a "model" of knowledge about an object.

    The knowledge base should contain as absolutely little redundant data
    as possible - effectively the most fundemental artifacts that we can
    use to efficiently reconstruct anything the user would want to know about.
    """

    def __init__(self, object, *args, **kwargs):
        """Initialization routine for KnowledgeBase.

        :param object:  A CLE Backend instance.
        :type object:   cle.Backend
        """
        self._plugins = {}
        # 8<----------------- Compatibility layer -----------------
        if not isinstance(object, cle.Backend):
            self._compat_init(object, *args, **kwargs)
            object = args[0]
        # ------------------- Compatibility layer --------------->8
        self._object = object

    def __getstate__(self):
        return self._object, self._plugins

    def __setstate__(self, state):
        self._object, self._plugins = state
        for name, plugin in self._plugins.items():
            self.register_plugin(name, plugin)

    def __getattr__(self, name):
        raise KnowledgeBaseNoPlugin("No such plugin: %s" % name)

    #
    #   ...
    #

    @property
    def object(self):
        return self._object

    def has_plugin(self, name):
        return name in self._plugins

    def register_plugin(self, name, plugin):
        self._plugins[name] = plugin
        self.__dict__[name] = plugin
        return plugin

    def release_plugin(self, name):
        if name in self._plugins:
            del self._plugins[name]
            del self.__dict__[name]

    #
    #   Compatibility layer
    #

    def get_plugin(self, name):
        return self._plugins[name]

    def _compat_init(self, project, obj):
        self._project = project
        self.obj = obj

        import knowledge_plugins
        self.register_plugin('functions', knowledge_plugins.FunctionManager(self))
        self.register_plugin('variables', knowledge_plugins.VariableManager(self))
        self.register_plugin('labels', knowledge_plugins.LabelsPlugin())
        self.register_plugin('resolved_indirect_jumps', set())
        self.register_plugin('unresolved_indirect_jumps', set())
        KnowledgeBase.callgraph = property(lambda self: self.functions.callgraph)
