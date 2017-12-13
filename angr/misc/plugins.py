from ..errors import NoPlugin


class PluginHub(object):
    """
    TODO: Update documentation.
    """

    def __init__(self):
        self._plugins = {}

    def __getstate__(self):
        return {'_plugins': self._plugins}

    def __setstate__(self, state):
        self._plugins = {}
        for name, plugin in state['_plugins'].items():
            self.register_plugin(name, plugin)

    def __getattr__(self, name):
        raise NoPlugin("No such plugin", name)

    #
    #   ...
    #

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


class PluginPreset(object):

    @classmethod
    def apply_preset(cls, hub, *args, **kwargs):
        raise NotImplementedError

    @classmethod
    def release_preset(cls, hub):
        raise NotImplementedError
