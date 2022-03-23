"""Representing the artifacts of a project."""

from itertools import count
import logging

from typing import TYPE_CHECKING, TypeVar, Type, Optional

if TYPE_CHECKING:
    from ..project import Project
    from ..knowledge_plugins import FunctionManager
    from ..knowledge_plugins import VariableManager
    from ..knowledge_plugins import KeyDefinitionManager
    from ..knowledge_plugins import CFGManager
    from ..knowledge_plugins import StructuredCodeManager
    from ..knowledge_plugins import TypesStore

from ..knowledge_plugins.plugin import default_plugins, KnowledgeBasePlugin

l = logging.getLogger(name=__name__)


kb_ctr = count(0, 1)


class KnowledgeBase:
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    functions: 'FunctionManager'
    variables: 'VariableManager'
    structured_code: 'StructuredCodeManager'
    defs: 'KeyDefinitionManager'
    cfgs: 'CFGManager'
    _project: 'Project'
    types: 'TypesStore'

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

    K = TypeVar("K", bound=KnowledgeBasePlugin)
    def get_knowledge(self, requested_plugin_cls: Type[K]) -> Optional[K]:
        """
        Type inference safe method to request a knowledge base plugin
        Explicitly passing the type of the requested plugin achieves two things:
        1. Every location using this plugin can be easily found with an IDE by searching explicit references to the type
        2. Basic type inference can deduce the result type and properly type check usages of it

        If there isn't already an instance of this class None will be returned to make it clear to the caller that there
        is no existing knowledge of this type yet. The code that initially creates this knowledge should use the
        `register_plugin` method to register the initial knowledge state
        :param requested_plugin_cls:
        :return: Instance of the requested plugin class or null if it is not a known plugin
        """
        # Get first plugin of this type already registered, or default to None
        return next(
            filter(lambda registered_plugin: type(registered_plugin) == requested_plugin_cls, self._plugins.values()),
            None)

    def request_knowledge(self, requested_plugin_cls: Type[K]) -> K:
        existing = self.get_knowledge(requested_plugin_cls)
        if existing is not None:
            return existing
        else:
            p = requested_plugin_cls(self)
            self.register_plugin(requested_plugin_cls.__name__, p)
            return p
