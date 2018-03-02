from ..errors import NoPlugin


class PluginHub(object):
    """
    TODO: Update documentation.
    """

    def __init__(self):
        super(PluginHub, self).__init__()
        self._default_plugins = {}
        self._active_plugins = {}
        self._active_preset = None

    def __getstate__(self):
        return {'_default_plugins': self._default_plugins,
                '_active_plugins': self._active_plugins,
                '_active_preset': self._active_preset}

    def __setstate__(self, s):
        self._default_plugins = {}
        self._active_plugins = {}
        self._active_preset = s.get('_active_preset')

        for name, plugin_cls in s.get('_default_plugins', {}).items():
            if name not in self._default_plugins:
                self.register_default(name, plugin_cls)

        for name, plugin_cls in s.get('_active_plugins', {}).items():
            if name not in self._active_plugins:
                self.register_plugin(name, plugin_cls)

    def __getattr__(self, item):
        try:
            return self.get_plugin(item)
        except NoPlugin:
            raise AttributeError

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
            self._active_preset.release_plugins(self)
        preset.register_plugins(self)
        self._active_preset = preset

    def discard_preset(self):
        self._active_preset.release_plugins(self)
        self._active_preset = None

    #
    #   ...
    #

    def get_plugin(self, name):
        if name in self._active_plugins:
            return self._active_plugins[name]
        elif name in self._default_plugins:
            plugin_cls = self._default_plugins[name]
            return self.register_plugin(name, self._init_plugin(plugin_cls))
        else:
            raise NoPlugin("No such plugin: %s", name)

    def has_plugin(self, name):
        return name in self._active_plugins

    def register_plugin(self, name, plugin):
        if self.has_plugin(name):
            self.release_plugin(name)
        self._active_plugins[name] = plugin
        self.__dict__[name] = plugin
        return plugin

    def release_plugin(self, name):
        del self._active_plugins[name]
        del self.__dict__[name]

    def release_all_plugins(self):
        for name in self._plugins:
            self.release_plugin(name)

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
