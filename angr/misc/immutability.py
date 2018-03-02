import abc
import contextlib


class ImmutabilityMixin(object):

    def __init__(self, immutable=False):
        super(ImmutabilityMixin, self).__init__()
        self._immutable = immutable

    @abc.abstractmethod
    def copy(self):
        raise NotImplementedError

    @classmethod
    def immutable(cls, method):
        """

        :param method:
        :return:
        """
        def _wrapper(self, *args, **kwargs):
            with cls.context(self) as self: #pylint:disable=redefined-argument-from-local
                if method(self, *args, **kwargs) is not self:
                    raise ImmutabilityMixinMisused
                return self
        return _wrapper

    @classmethod
    @contextlib.contextmanager
    def context(cls, obj):
        was_immutable = obj._immutable
        if was_immutable:
            obj = obj.copy()
            obj._immutable = False
        yield obj
        obj._immutable = was_immutable


class ImmutabilityMixinMisused(Exception):

    def __init__(self):
        super(ImmutabilityMixinMisused, self).\
            __init__('Immutable methods are expected to return the new self object')
