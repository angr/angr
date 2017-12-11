from contextlib import contextmanager


class KnowledgeView(object):
    """
    This represents a view over the knowledge that is provided by the knowledge base.

    The purpose of the view is to interpret an assorted set of different articats
    into a more general knowledge about a given object. For example, given the list
    of basic blocks and the results of indirect jump resolution, a full transition graph
    view can be constructed.

    :cvar _sync_lock:   A list of already synced views. This is to prevent multiple
                        cache updates in nested calls to different views.
    """
    _sync_lock = []

    def __init__(self, kb):
        super(KnowledgeView, self).__init__()
        self._kb = kb

    @property
    def kb(self):
        return self._kb

    @staticmethod
    def syncedmethod(func):
        """
        A convinience decorator that could be used to wrap those methods, which rely on
        the cached KB state.

        :param func:    A method to wrap.
        :return:
        """
        def _synced(self, *args, **kwargs):
            with self._sync_caches():
                return func(self, *args, **kwargs)
        return _synced

    @contextmanager
    def _sync_caches(self):
        """
        The purpose of this context manager is to ensure that the latest KB
        changes are pulled to internal caches prior to executing the rest
        of the context.

        :return:
        """
        # If not already synced...
        if self not in self._sync_lock:
            self._sync_lock.append(self)
            self._do_sync_caches()

        yield

        if self._sync_lock:
            if self._sync_lock[0] is self:
                # This view has started the sync chain, so no more nested calls
                # will occur. Now we must mark all the involved views as not synced.
                del self._sync_lock[:]

    def _do_sync_caches(self):
        """An internal function that does the actual cache synchronization.
        Must be overriden by a subclass if the syncedmethod() decorator
        is to be used.

        :return:
        """
        raise NotImplementedError
