import functools

from ..misc.observer import Observer, Observable


class KnowledgeBasePlugin(Observer, Observable):
    """
    This is a knowledge base plugin. It's purpose is to provide a generic
    interface for plugin registration and inter-communication.

    A knowledge base plugin is designed to be used in the terms of
    Provider-Consumer model. In this model each plugin acts as a knowledge
    provider and/or  knowledge consumer, where it can provide a new knowledge
    either by exposing an interface to access a set of stored artifacts (e.g.
    obtained from some kind of a binary static analysis, see KnowledgeArtifact),
    or by interpreting a knowledge bits, provided by other plugins, thus extracting
    a new knowledge from an already present one.

    Consider the following example:

                +--------------+  +----------------+
                | basic_blocks |  | indirect_jumps |
                |      A       |  |       A        |
                +---+--------+-+  +--+-------------+
                    |        |       |
                    v        v       v
                +---+----+ +-+-------+---+
                | blocks | | transitions |
                |   V    | |      V      |
                +-+------+ +-----------+-+
                  |                    |
                  |                    |
                  |    +-----------+   |
                  +--->+ functions +<--+
                       |     V     |
                       +-+-------+-+
                         ^       ^
                         |       |
                +--------+-+ +---+-------------+
                |  labels  | | function_chunks |
                |    A     | |        A        |
                +----------+ +-----------------+

    where A - KnowledgeArtifact, V - KnowledgeView.

    Here we can see a "knowledge-flow diagram" (tm), where the arrows goes from
    producer to consumer. For example, given a knowledge about boundaries and
    contents of basic blocks, that are stored in 'basic_blocks' plugin, and
    the results of indirect jump resolution, that are stored in 'indirect_jumps'
    plugin, a full transition graph view can be constructed by interpreting the
    facts, provided by them.

    The Observer mixin allows the view to be notified about all the recently
    discovered bits of knowledge, thus enabling the production a more general
    knowledge in runtime.

    The Observable mixin allows all the interested parties to register themselves
    as observers, in order to be continuously notified, if the new artifacts has
    been obtained.

    For the notification to be made, a subclass should call _update_observers()
    method, passing all the neccessary information about the new artifact as
    a keyword arguments.

    All the plumbings that are needed to be done in order to connect
    knowledge consumers with knowledge providers and vice versa are done in the
    initialization routine of KnowledgePlugin, based on the values given in
    the `provides` and `consumes` keyword arguments. The `provides` keyword
    argument specifies the exact kind of knowledge which the plugin should
    provide. Aside from being a short description of what kind of knowledge
    bits could be found within the plugin's data, it is used by the plugin
    observers to detect from which observable the particular notification
    came from.

    On the other side, the `consumes` keyword specifies a set of providers,
    from which the plugin wishes to receive notifications about new knowledge.
    """

    def __init__(self, kb, provides=None, consumes=None):
        """KnowledgePlugin initializtion routine.

        :param kb:          The knowledge base that this plugin is bound to.
        :type kb:           angr.KnowledgeBase
        :param provides:    A string specifying an exact kind of knowledge which
                            this plugin provides.
        :type provides:     str
        :param consumes:    A set of strings which specifies the kinds of
                            knowledge which this plugin consumes.
        :type consumes:     set, tuple, list
        """
        super(KnowledgeBasePlugin, self).__init__()
        self._kb = kb

        # If the plugin is a knowledge provider, it should have means
        # to notify registered consumers about a obtaining new knowledge
        self._provides = provides

        # If the plugin is a knowledge consumer, it should register
        # itself to a set of corresponding knowledge providers
        if consumes:
            for plugin in map(self._kb.get_plugin, consumes):
                plugin.register(self)

    def _observe(self, source, event, **kwargs):
        """Register an `event` that came from the `source` and take
        the appropriate actions.

        @TODO: An actual description.

        E.g. '_observe_%s_%s' % ('basic_blocks', 'add_block').

        :param source:  The name of knowledge provider.
        :param event:   What has happened.
        :param kwargs:  Additional info.
        :return:
        """
        handler_name = '_observe_%s_%s' % (source, event)
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            handler(**kwargs)

    def _update_observers(self, event, **kwargs):
        """Notify consumers about a new knowledge that has been obtained.

        @TODO: An actual description.

        :param source:  The name of knowledge provider.
        :param event:   What has happened.
        :param kwargs:  Additional info
        :return:
        """
        super(KnowledgeBasePlugin, self)._update_observers(self._provides, event, **kwargs)
