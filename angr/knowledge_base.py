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

    def __new__(cls, *args, **kwargs):
        if args and not isinstance(args[0], cle.Backend):
            return super(KnowledgeBase, cls).__new__(CompatKnowledgeBase, *args, **kwargs)
        return super(KnowledgeBase, cls).__new__(cls, *args, **kwargs)

    def __init__(self, object):
        """Initialization routine for KnowledgeBase.

        :param object:  A CLE Backend instance.
        :type object:   cle.Backend
        """
        self._plugins = {}
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

    def get_plugin(self, name):
        return self._plugins[name]

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


class CompatKnowledgeBase(KnowledgeBase):
    """
    TODO: Update documentation.
    """

    def __init__(self, project, object):
        super(CompatKnowledgeBase, self).__init__(object)
        self._project = project

        from knowledge_plugins import PLUGIN_PRESET
        PLUGIN_PRESET['compat'].apply_preset(self)

    @property
    def obj(self):
        return self._object

    @property
    def callgraph(self):
        return self.functions.callgraph
