
from .errors import SimStateOptionsError


_NO_DEFAULT_VALUE = "_NO_DEFAULT_VALUE"  # please god don't use this value as the default value of your state option


class StateOption(object):
    """
    Describes a state option.
    """

    __slots__ = [ 'name', 'types', 'default', 'description' ]

    def __init__(self, name, types, default=_NO_DEFAULT_VALUE, description=None):
        self.name = name
        self.types = tuple(types)
        self.default = default
        self.description = description

        # Sanity check
        if not isinstance(self.default, tuple(self.types)):
            raise SimStateOptionsError("The type of the default value does not match the expected types of this state "
                                       "option.")

    @property
    def has_default_value(self):
        return self.default != _NO_DEFAULT_VALUE

    def one_type(self):
        if len(self.types) == 1:
            return next(iter(self.types))

        return None

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, StateOption) \
               and self.name == other.name \
               and self.types == other.types

    def __repr__(self):
        if self.description is not None:
            desc = ": %s" % self.description
        else:
            desc = ""
        if self.one_type() is not None:
            types = self.one_type().__name__
        else:
            types = ",".join(t.__name__ for t in self.types)

        return "<O %s[%s]%s>" % (self.name, types, desc)


class SimStateOptions(object):
    """
    A per-state manager of state options. An option can be either a key-valued entry or a Boolean switch (which can be
    seen as a key-valued entry whose value can only be either True or False).
    """

    OPTIONS = { }

    def __init__(self, thing):
        """
        :param thing:    Either a set of Boolean switches to enable, or an existing SimStateOptions instance.
        """

        self._options = { }
        if thing is None:
            pass
        elif isinstance(thing, (set, list)):
            boolean_switches = thing
            for name in boolean_switches:
                self[name] = True
        elif isinstance(thing, SimStateOptions):
            ops = thing
            self._options = ops._options.copy()
        else:
            raise SimStateOptionsError("Unsupported constructor argument type '%s'." % type(thing))

    def _get_option_desc(self, key):
        """
        Get the option descriptor from self.OPTIONS.

        :param str key: Name of the state option.
        :return:        The option descriptor.
        :rtype:         StateOption
        """

        if key not in self.OPTIONS:
            raise SimStateOptionsError("The state option '%s' does not exist." % key)

        return self.OPTIONS[key]

    def __repr__(self):
        s = "<SimStateOptions>"
        return s

    def __contains__(self, key):
        """
        [COMPATIBILITY]
        In order to be compatible with the old interface, __contains__() only supports testing the value of a Boolean
        switch.

        E.g., in the old days:
        >>> sim_options.SYMBOLIC in state.options
        False

        nowadays:
        >>> sim_options.SYMBOLIC in state.options
        False

        But you cannot use it to test the value of a non-existent option, or the value of a key-valued entry that is not
        linked to a Boolean value.

        >>> "symbolic_ip_max_targets" in state.options
        SimStateOptionsError('"symbolic_ip_max_targets" is not a Boolean switch.')

        :param str key: Name of the Boolean switch.
        :return:        True if the switch is on (the option is switched on), False otherwise.
        :rtype:         bool
        """

        o = self._get_option_desc(key)

        if o.one_type() is not bool:
            raise SimStateOptionsError("The state option '%s' is not a Boolean switch." % key)

        return key in self._options and self._options[key] is True

    def __setitem__(self, key, value):
        """
        Set the value of a state option.

        :param str key:     Name of the state option.
        :param str value:   The value of the state option. Must be of the same type as registered.
        :return:            None
        """

        o = self._get_option_desc(key)

        if type(value) not in o.types:
            raise SimStateOptionsError("The value '%s' does not have an acceptable type for state option '%s'. "
                                       "Accepted types are: %s." %
                                       (value, key, str(o.types))
                                       )

        self._options[o.name] = value

    def __getitem__(self, key):
        """
        Get the value of a state option.

        :param str key: Name of the state option.
        :return:        Value of the state option.
        """

        o = self._get_option_desc(key)

        if o.name not in self._options:
            # Special handling for Boolean switches
            if o.one_type() is bool:
                return o.default

            # Special handling for options with default values
            if o.has_default_value:
                return o.default

        return self._options[o.name]

    def __ior__(self, boolean_switches):
        """
        [COMPATIBILITY]
        In order to be compatible with the old interface, you can enable a collection of Boolean switches at the same
        time by doing the following:

        >>> state.options |= {sim_options.SYMBOLIC, sim_options.ABSTRACT_MEMORY}

        :param set boolean_switches:    A collection of Boolean switches to enable.
        :return:                        self
        """

        for name in boolean_switches:
            self[name] = True
        return self

    def __isub__(self, boolean_switches):
        """
        [COMPATIBILITY]
        In order to be compatible with the old interface, you can disable a collection of Boolean switches at the same
        time by doing the following:

        >>> state.options -= {sim_options.SYMBOLIC, sim_options.ABSTRACT_MEMORY}

        :param set boolean_switches:    A collection of Boolean switches to disable.
        :return:                        self
        """

        for name in boolean_switches:
            self[name] = False
        return self

    def __getattr__(self, key):
        if key in { 'OPTIONS', '_options' }:
            return self.__getattribute__(key)
        return self[key]

    def __setattr__(self, key, value):
        if key in { 'OPTIONS', '_options' }:
            super(SimStateOptions, self).__setattr__(key, value)
            return
        self[key] = value

    def add(self, boolean_switch):
        """
        [COMPATIBILITY]
        Enable a Boolean switch.

        :param str boolean_switch:  Name of the Boolean switch.
        :return:                    None
        """

        self[boolean_switch] = True

    def discard(self, boolean_switch):
        """
        [COMPATIBILITY]
        Disable a Boolean switch.

        :param str boolean_switch:  Name of the Boolean switch.
        :return:                    None
        """

        self[boolean_switch] = False

    def difference(self, boolean_switches):
        """
        [COMPATIBILITY]
        Make a copy of the current instance, and then discard all options that are in boolean_switches.

        :param set boolean_switches:    A collection of Boolean switches to disable.
        :return:                        A new SimStateOptions instance.
        """

        ops = SimStateOptions(self)
        for key in boolean_switches:
            ops.discard(key)
        return ops

    def tally(self, description=False):
        """
        Return a string representation of all state options.

        :param bool description:    Whether to display the description of each option.
        :return:                    A string representation.
        :rtype:                     str
        """

        total = [ ]

        for o in sorted(self.OPTIONS.values(), key=lambda x: x.name):
            try:
                value = self[o.name]
            except SimStateOptionsError:
                value = "<Unset>"
            s = "{option}: {value}".format(option=o.name, value=value)
            if description:
                s += " | {description}".format(description=o.description)

            total.append(s)

        return "\n".join(total)

    @classmethod
    def register_option(cls, name, types, default=None, description=None):
        """
        Register a state option.

        :param str name:        Name of the state option.
        :param types:           A collection of allowed types of this state option.
        :param default:         The default value of this state option.
        :param str description: The description of this state option.
        :return:                None
        """

        if name in cls.OPTIONS:
            raise SimStateOptionsError("A state option with the same name has been registered.")

        if isinstance(types, type):
            types = { types }

        o = StateOption(name, types, default=default, description=description)
        cls.OPTIONS[name] = o

    @classmethod
    def register_bool_option(cls, name, description=None):
        """
        Register a Boolean switch as state option.
        This is equivalent to cls.register_option(name, set([bool]), description=description)

        :param str name:        Name of the state option.
        :param str description: The description of this state option.
        :return:                None
        """

        cls.register_option(name, { bool }, default=False, description=description)
