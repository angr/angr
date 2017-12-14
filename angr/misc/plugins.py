from ..errors import NoPlugin


class PluginHub(object):
    """
    TODO: Update documentation.
    """

    def __init__(self):
        super(PluginHub, self).__init__()
        self._plugins = {}
        self._default_plugins = {}
        self._active_preset = None

    def __getstate__(self):
        return {'_plugins': self._plugins,
                '_default_plugins': self._default_plugins}

    def __setstate__(self, state):
        self._plugins = {}
        for name, plugin in state['_plugins'].items():
            self.register_plugin(name, plugin)
        self._default_plugins = state['_default_plugins']

    def __getattr__(self, name):
        return self.get_plugin(name)

    #
    #   ...
    #

    @property
    def preset(self):
        return self._active_preset

    def has_preset(self):
        return self._active_preset is not None

    def use_preset(self, preset):
        if self._active_preset:
            self._active_preset.release_plugins()
        preset.register_plugins(self)
        self._active_preset = preset

    def discard_preset(self):
        self._active_preset.release_plugins()
        self._active_preset = None

    #
    #   ...
    #

    def get_plugin(self, name):
        if name in self._plugins:
            return self._plugins[name]
        elif name in self._default_plugins:
            plugin_cls = self._default_plugins[name]
            return self.register_plugin(name, self._init_plugin(plugin_cls))
        else:
            raise NoPlugin("No such plugin: %s", name)

    def has_plugin(self, name):
        return name in self._plugins

    def register_plugin(self, name, plugin):
        if self.has_plugin(name):
            self.release_plugin(name)
        self._plugins[name] = plugin
        self.__dict__[name] = plugin
        return plugin

    def release_plugin(self, name):
        del self._plugins[name]
        del self.__dict__[name]

    #
    #   ...
    #

    def has_default(self, name):
        return name in self._default_plugins

    def register_default(self, name, plugin_cls):
        self._default_plugins[name] = plugin_cls

    def release_default(self, name):
        if name in self._default_plugins:
            del self._default_plugins[name]

    def _init_plugin(self, plugin_cls):
        return plugin_cls()


class PluginPreset(object):

    def register_plugins(self, hub):
        raise NotImplementedError

    def release_plugins(self, hub):
        pass
