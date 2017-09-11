from .plugin import KnowledgeBasePlugin
from ..misc.observer import Observer


class KnowledgeBaseView(KnowledgeBasePlugin, Observer):
    """
    This represents a view over the knowledge that is proveided by the knowledge base.

    The purpose of the view is to interpret an assorted set of different articats
    into a more general knowledge about a given object. For example, given the list
    of basic blocks and the results of indirect jump resolution, a full transition graph
    view can be constructed.

    Optionally, a view could provide a means for dissecting a general knowledge
    into a set of knowledge artifacts, e.g. allowing to define a function with
    a given name, thus adding a new label and a bb local group, or to interpret
    an angr.Block into a basic block.

    The Observer mixin allows the view to be notified about all the recently
    discovered bits of knowledge, thus enabling the production a more general
    knowledge in runtime.

    :var _depends:  a list of artifact names which this view depends on
                    (see KnowledgeArtifact._provides).
    """
    _depends = []

    def __init__(self, kb):
        super(KnowledgeBaseView, self).__init__(kb)

    def reconstruct(self):
        """Reconstruct a view from knowledge base, discarding all the cached
        objects and creating a new ones from scratch.

        :return:
        """
        pass

    def _observe(self, observable, action, **kwargs):
        """Handle the notification about `action` taken by `observable`.

        :param observable:
        :param action:
        :param kwargs:
        :return:
        """
        handler = '_%s_%s' % (observable, action)
        if hasattr(self, handler):
            handle = getattr(self, handler)
            handle(**kwargs)

    def _init_view(self):
        """KnowledgeBaseView internal initialization routine.

        This should be called by the subclass after it finishes its initializtion.

        :return:
        """
        # First, process all the already present knowledge in the knowledge base.
        self.reconstruct()

        # Register this view as an observer of the knowledge artifacts, which
        # names are present in the `observers` class property.
        for plugin in map(self._kb.get_plugin, self._depends):
            plugin.register(self)
