from ..misc.plugins import PluginHub
from ..errors import NoPlugin


class EngineHub(PluginHub):

    def __init__(self):
        super(EngineHub, self).__init__()
        self.processing_order = []

    def __iter__(self):
        return (self.get_plugin(name) for name in self.processing_order)

    def __getstate__(self):
        s = super(EngineHub, self).__getstate__()
        s['processing_order'] = self.processing_order
        return s

    def __setstate__(self, s):
        super(EngineHub, self).__setstate__(s)
        self.processing_order = s['processing_order']

    @property
    def default_engine(self):
        try:
            return self.get_plugin('default')
        except NoPlugin:
            return None

    @property
    def procedure_engine(self):
        try:
            return self.get_plugin('procedure')
        except NoPlugin:
            return None
