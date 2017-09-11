from .plugin import KnowledgeBasePlugin
from ..misc.observer import Observable


class KnowledgeArtifact(KnowledgeBasePlugin, Observable):
    """
    This represents one specific set of homogeneous artifacts about
    given object. These artifacts can be, for example, basic blocks
    boundaries, the results of the resolution of indirect jumps, and so on.

    The Observable mixin allows all the interested parties to register themselves
    as observers, in order to be continuously notified, if the new artifacts has
    been obtained.

    For the notification to be made, a subclass should call _notify_observers()
    method, passing all the neccessary information about the new artifact as
    a keyword arguments.

    :var _provides: the name of the artifact which this plugin provdes
                    (see KnowledgeView._depends).
    """
    _provides = 'plugin'

    def __init__(self, kb):
        super(KnowledgeArtifact, self).__init__(kb)

    def _notify_observers(self, action, **kwargs):
        self._update_observers(self._provides, action, **kwargs)
