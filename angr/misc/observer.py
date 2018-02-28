from abc import ABCMeta, abstractmethod


class Observable(object):
    """

    """

    def __init__(self, *args, **kwargs):
        super(Observable, self).__init__()
        self._observers = []

    def register(self, observer):
        if observer not in self._observers:
            self._observers.append(observer)

    def unregister(self, observer):
        if observer in self._observers:
            self._observers.remove(observer)

    def unregister_all(self):
        if self._observers:
            del self._observers[:]

    def _update_observers(self, *args, **kwargs):
        for observer in self._observers:
            observer._observe(*args, **kwargs)


class Observer(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def _observe(self, *args, **kwargs):
        pass
