from typing import Type, Dict, Optional, List, TypeVar, Generic

from angr.errors import AngrNoPluginError

import logging

l = logging.getLogger(name=__name__)

P = TypeVar("P")


class PluginHub(Generic[P]):
    """
    A plugin hub is an object which contains many plugins, as well as the notion of a "preset", or a
    backer that can provide default implementations of plugins which cater to a certain
    circumstance.

    Objects in angr like the SimState, the Analyses hub, the SimEngine selector, etc all use this
    model to unify their mechanisms for automatically collecting and selecting components to use. If
    you're familiar with design patterns this is a configurable Strategy Pattern.

    Each PluginHub subclass should have a corresponding Plugin subclass, and perhaps a PluginPreset
    subclass if it wants its presets to be able to specify anything more interesting than a list of
    defaults.
    """

    def __init__(self):
        super().__init__()
        self._active_plugins: Dict[str, P] = {}
        self._active_preset: Optional[PluginPreset] = None
        self._provided_by_preset: List[int] = []

    #
    #   Class methods for registration
    #

    _presets: Dict[str, Type[P]]

    @classmethod
    def register_default(cls, name, plugin_cls, preset="default"):
        if not hasattr(cls, "_presets") or preset not in cls._presets:
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
        if not hasattr(cls, "_presets"):
            cls._presets = {}
        cls._presets[name] = preset

    #
    #   Python magic methods
    #

    def __getstate__(self):
        return self._active_plugins, self._active_preset, self._provided_by_preset

    def __setstate__(self, s):
        plugins, preset, provided = s
        self._active_preset = preset
        self._active_plugins = {}
        self._provided_by_preset = provided

        for name, plugin in plugins.items():
            if name not in self._active_plugins:
                self.register_plugin(name, plugin)

    def __getattr__(self, name: str) -> P:
        try:
            return self.get_plugin(name)
        except AngrNoPluginError:
            raise AttributeError(name)

    def __dir__(self):
        out = set(self.__dict__)
        out.update(self._active_plugins)
        if self.has_plugin_preset:
            out.update(self._active_preset.list_default_plugins())

        q = [type(self)]
        while q:
            cls = q.pop(0)
            out.update(cls.__dict__)
            for base in cls.__bases__:
                if base is not object:
                    q.append(base)

        return sorted(out)

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
    def has_plugin_preset(self) -> bool:
        """
        Check whether or not there is a plugin preset in use on this hub right now
        """
        return self._active_preset is not None

    def use_plugin_preset(self, preset):
        """
        Apply a preset to the hub. If there was a previously active preset, discard it.

        Preset can be either the string name of a preset or a PluginPreset instance.
        """
        if isinstance(preset, str):
            try:
                preset = self._presets[preset]
            except (AttributeError, KeyError):
                raise AngrNoPluginError("There is no preset named %s" % preset)

        elif not isinstance(preset, PluginPreset):
            raise ValueError("Argument must be an instance of PluginPreset: %s" % preset)

        if self._active_preset:
            l.warning("Overriding active preset %s with %s", self._active_preset, preset)
            self.discard_plugin_preset()

        preset.activate(self)
        self._active_preset = preset

    def discard_plugin_preset(self):
        """
        Discard the current active preset. Will release any active plugins that could have come from the old preset.
        """
        if self.has_plugin_preset:
            for name, plugin in list(self._active_plugins.items()):
                if id(plugin) in self._provided_by_preset:
                    self.release_plugin(name)
            self._active_preset.deactivate(self)
        self._active_preset = None

    #
    #   Methods for managing the current active plugins
    #

    def get_plugin(self, name: str) -> P:
        """
        Get the plugin named ``name``. If no such plugin is currently active, try to activate a new
        one using the current preset.
        """
        if name in self._active_plugins:
            return self._active_plugins[name]

        elif self._active_preset is not None:
            plugin_cls: Type[P] = self._active_preset.request_plugin(name)
            plugin = self._init_plugin(plugin_cls)

            # Remember that this plugin was provided by preset.
            self._provided_by_preset.append(id(plugin))

            self.register_plugin(name, plugin)
            return plugin

        else:
            raise AngrNoPluginError("No such plugin: %s" % name)

    def _init_plugin(self, plugin_cls: Type[P]) -> P:  # pylint: disable=no-self-use
        """
        Perform any initialization actions on plugin before it is added to the list of active plugins.

        :param plugin_cls:
        """
        return plugin_cls()

    def has_plugin(self, name):
        """
        Return whether or not a plugin with the name ``name`` is currently active.
        """
        return name in self._active_plugins

    def register_plugin(self, name: str, plugin):
        """
        Add a new plugin ``plugin`` with name ``name`` to the active plugins.
        """
        if self.has_plugin(name):
            self.release_plugin(name)
        self._active_plugins[name] = plugin
        setattr(self, name, plugin)
        return plugin

    def release_plugin(self, name):
        """
        Deactivate and remove the plugin with name ``name``.
        """
        plugin = self._active_plugins[name]
        if id(plugin) in self._provided_by_preset:
            self._provided_by_preset.remove(id(plugin))

        del self._active_plugins[name]
        delattr(self, name)


class PluginPreset:
    """
    A plugin preset object contains a mapping from name to a plugin class.
    A preset can be active on a hub, which will cause it to handle requests for plugins which are not already present
    on the hub.

    Unlike Plugins and PluginHubs, instances of PluginPresets are defined on the module level for individual presets.
    You should register the preset instance with a hub to allow plugins to easily add themselves to the preset without
    an explicit reference to the preset itself.
    """

    def __init__(self):
        self._default_plugins: Dict[str, Type[P]] = {}

    def activate(self, hub):  # pylint:disable=no-self-use,unused-argument
        """
        This method is called when the preset becomes active on a hub.
        """
        return

    def deactivate(self, hub):  # pylint:disable=no-self-use,unused-argument
        """
        This method is called when the preset is discarded from the hub.
        """
        return

    def add_default_plugin(self, name, plugin_cls):
        """
        Add a plugin to the preset.
        """
        self._default_plugins[name] = plugin_cls

    def list_default_plugins(self):
        """
        Return a list of the names of available default plugins.
        """
        return self._default_plugins.keys()

    def request_plugin(self, name: str) -> Type[P]:
        """
        Return the plugin class which is registered under the name ``name``, or raise NoPlugin if
        the name isn't available.
        """
        try:
            return self._default_plugins[name]
        except KeyError:
            raise AngrNoPluginError("There is no plugin named %s" % name)

    def copy(self):
        """
        Return a copy of self.
        """
        cls = self.__class__
        result = cls.__new__(cls)
        result._default_plugins = dict(self._default_plugins)  # pylint:disable=protected-access
        return result


class PluginVendor(Generic[P], PluginHub[P]):
    """
    A specialized hub which serves only as a plugin vendor, never having any "active" plugins.
    It will directly return the plugins provided by the preset instead of instanciating them.
    """

    def release_plugin(self, name):
        pass

    def register_plugin(self, name, plugin):
        pass

    def __dir__(self):
        x = super().__dir__()
        x.remove("release_plugin")
        x.remove("register_plugin")
        x.remove("has_plugin")
        return x


class VendorPreset(PluginPreset):
    """
    A specialized preset class for use with the PluginVendor.
    """

    ...
