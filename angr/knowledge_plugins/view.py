from abc import ABCMeta

from .plugin import KnowledgeBasePlugin


class KnowledgeBaseViewMeta(ABCMeta):
    """
    This is an utilitary meta class which is made with a sole purpose
    of deferring the call to reconstruct() method to the post-initializtion
    stage, thus allowing the initialization of the instance variables
    prior to reconstruction.

    In practice, this results in

    # with KnowledgeBaseViewMeta
    class FooView(KnowledgeBaseView):
        def __init__(kb, ...):
            super(FooView, self).__init__(kb, ...)
            self.bar = 0

                        vs

    # without KnowledgeBaseViewMeta
    class FooView(KnowledgeBaseView):
        def __init__(kb, ...):
            self.bar = 0
            super(FooView, self).__init__(kb, ...)

    Optionally, this meta-class enables "reconstruction-on-demand" by accepting
    a `reconstruct` keyword. Should be useful, eh?
    """

    def __call__(cls, *args, **kwargs):
        view = type.__call__(cls, *args, **kwargs)
        if kwargs.pop('reconstruct', True):
            view.reconstruct()
        return view


class KnowledgeBaseView(KnowledgeBasePlugin):
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

    The knowledge view could be a knowledge provider and consumer at the same time.
    """
    __metaclass__ = KnowledgeBaseViewMeta

    def __init__(self, kb, provides=None, consumes=None, **kwargs):
        super(KnowledgeBaseView, self).__init__(kb, provides, consumes)

    def reconstruct(self):
        """Reconstruct a view from knowledge base, discarding all the cached
        objects and creating a new ones from scratch.

        :return:
        """
        pass
