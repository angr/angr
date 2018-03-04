import logging

from ..errors import NoPlugin

l = logging.getLogger(name=__name__)

class PluginHub(object):
    """
    A plugin hub is an object which contains many plugins, as well as the notion of a "preset", or a backer that can
    provide default implementations of plugins which cater to a certain circumstance.

    Objects in angr like the SimState, the Analyses hub, the SimEngine selector, etc all use this model to unify their
    mechanisms for automatically collecting and selecting components to use. If you're familiar with design patterns this is a configurable Strategy Pattern.

    Each PluginHub subclass should have a corresponding Plugin subclass, and perhaps a PluginPreset subclass if it
    wants its presets to be able to specify anything more interesting than a list of defaults.
    """

    def __init__(self):
        super(PluginHub, self).__init__()
        self._active_plugins = {}
        self._active_preset = None

    #
    #   Class methods for registration
    #

    _presets = None # not a dict so different subclasses don't share instances

    @classmethod
    def _register_default(cls, name, plugin_cls, preset):
        if cls._presets is None or preset not in cls._presets:
            l.error("Preset %s does not exist yet...", preset)
            return
        cls._presets[preset].add_default_plugin(name, plugin_cls)

    @classmethod
    def register_preset(cls, name, preset):
        """
        Register a preset instance with the class of the hub it corresponds to. This allows individual plugin objects to
        automatically register themselves with a preset by using a classmethod of their own with only the name of the
        preset to register with.
        """
        if cls._presets is None:
            cls._presets = {}
        cls._presets[name] = preset

    #
    #   Python magic methods
    #

    def __getstate__(self):
        return (self._active_plugins, self._active_preset)

    def __setstate__(self, s):
        plugins, preset = s
        self._active_preset = preset
        self._active_plugins = {}

        for name, plugin in plugins.items():
            if name not in self._active_plugins:
                self.register_plugin(name, plugin)

    def __getattr__(self, name):
        try:
            return self.get_plugin(name)
        except NoPlugin:
            raise AttributeError(name)

    def __dir__(self):
        out = set(self._active_plugins)
        out.update(super(PluginHub, self).__dir__())
        if self._active_preset is not None:
            out.update(self._active_preset.list_default_plugins())
        return list(out)

    #
    #   Methods for managing the current plugin preset
    #

    @property
    def plugin_preset(self):
        """
        Get the current active plugin preset
        """
        return self._active_preset

    @property
    def has_plugin_preset(self):
        """
        Check whether or not there is a plugin preset in use on this hub right now
        """
        return self._active_preset is not None

    def use_plugin_preset(self, preset):
        """
        Apply a preset to the hub. If there was a previously active preset, discard it.

        Preset can be either the string name of a preset or a PluginPreset instance.
        """
        if self._active_preset:
            l.warning("Overriding active preset %s with %s", self._active_preset, preset)
            self.discard_plugin_preset()

        if type(preset) is bytes:
            try:
                preset = self._presets[preset]
            except (AttributeError, KeyError):
                raise NoPlugin("There is no preset named %s" % preset)

        self._active_preset = preset

    def discard_plugin_preset(self):
        """
        Discard the current active preset. Will release any active plugins that could have come from the old preset.
        """
        if self.has_plugin_preset:
            for plugin in self._active_preset.list_default_plugins():
                if plugin in self._active_plugins and \
                        type(self._active_plugins) is self._active_preset.default_plugins[plugin]:
                    self.release_plugin(plugin)
        self._active_preset = None

    #
    #   Methods for managing the current active plugins
    #

    def get_plugin(self, name):
        """
        Get the plugin named ``name``. If no such plugin is currently active, try to activate a new one using the current preset.
        """
        if name in self._active_plugins:
            return self._active_plugins[name]

        if self._active_preset is not None:
            try:
                plugin = self._init_plugin(self._active_preset.new_plugin(name))
            except NoPlugin:
                pass
            else:
                self.register_plugin(name, plugin)
                return plugin

        raise NoPlugin("No such plugin: %s" % name)

    def _init_plugin(self, plugin): # pylint: disable=no-self-use
        return plugin()

    def has_plugin(self, name):
        """
        Return whether or not a plugin with the name ``name`` is curently active.
        """
        return name in self._active_plugins

    def register_plugin(self, name, plugin):
        """
        Add a new plugin ``plugin`` with name ``name`` to the active plugins.
        """
        if self.has_plugin(name):
            self.release_plugin(name)
        self._active_plugins[name] = plugin
        return plugin

    def release_plugin(self, name):
        """
        Deactivate and remove the plugin with name ``name``.
        """
        del self._active_plugins[name]


class Plugin(object):
    """
    This is the base class for all plugin objects.
    It defines nothing but the ability to register itself with a hub.

    Subclasses of this should at the very least set the class variable ``_hub_type`` to the type of the PluginHub they apply to.
    """
    _hub_type = None

    @classmethod
    def register_default(cls, name, preset='default'):
        cls._hub_type._register_default(name, cls, preset)


class PluginPreset(object):
    """
    A plugin preset object contains a mapping from name to a plugin class.
    A preset can be active on a hub, which will cause it to handle requests for plugins which are not already present on the hub.

    Unlike Plugins and PluginHubs, instances of PluginPresets are defined on the module level for individual presets.
    You should register the preset instance with a hub to allow plugins to easily add themselves to the preset without an explicit reference to the preset itself.
    """
    def __init__(self):
        self.default_plugins = {}

    def add_default_plugin(self, name, plugin_cls):
        """
        Add a plugin to the preset
        """
        self.default_plugins[name] = plugin_cls

    def list_default_plugins(self):
        """
        Return an iterator over the names of available default plugins
        """
        return self.default_plugins.keys()

    def new_plugin(self, name):
        """
        Instanciate and return the plugin with the name ``name``, or raise NoPlugin if the name isn't availble
        """
        if name not in self.default_plugins:
            raise NoPlugin

        return self.default_plugins[name]

class PluginVendor(PluginHub):
    """
    A specialized hub which serves only as a plugin vendor, never having any "active" plugins.
    It will directly return the plugins provided by the preset instead of instanciating them.
    """
    def register_plugin(self, name, plugin):
        pass

    def __dir__(self):
        x = super(PluginVendor, self).__dir__()
        x.remove('release_plugin')
        x.remove('register_plugin')
        x.remove('has_plugin')
        return x

class VendorPreset(PluginPreset):
    """
    A specialized preset class for use with the PluginVendor
    """
    def new_plugin(self, name):
        if name not in self.default_plugins:
            raise NoPlugin

        return self.default_plugins[name]
