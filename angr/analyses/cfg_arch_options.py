
class CFGArchOptions(object):
    """
    Stores architecture-specific options and settings, as well as the detailed explanation of those options and
    settings.

    Suppose `ao` is the CFGArchOptions object, and there is an option called `ret_jumpkind_heuristics`, you can access
    it by
        `ao.ret_jumpkind_heuristics`
        and set its value via
        `ao.ret_jumpkind_heuristics = True`

    :ivar dict OPTIONS: A dict of all default options for different architectures.
    :ivar archinfo.Arch arch: The architecture object.
    :ivar dict _options: Values of all CFG options that are specific to the current architecture.
    """

    OPTIONS = {
        'ARMEL': {
            'ret_jumpkind_heuristics': (bool, True),  # option name: (option value type, default option value)
        },
        'ARMHF': {
            'ret_jumpkind_heuristics': (bool, True),
        },
    }

    arch = None
    _options = {}

    def __init__(self, arch, **options):
        """
        Constructor.

        :param archinfo.Arch arch: The architecture instance.
        :param dict options: Architecture-specific options, which will be used to initialize this object.
        """

        self.arch = arch

        self._options = {}

        if self.arch.name in self.OPTIONS:
            for k, (_, value) in self.OPTIONS[self.arch.name].iteritems():
                self._options[k] = value

        for k, v in options.iteritems():
            self.__setattr__(k, v)

    def __getattr__(self, option_name):
        if option_name in self._options:
            return self._options[option_name]

        return self.__getattribute__(option_name)

    def __setattr__(self, option_name, option_value):
        if option_name in self._options:

            # type checking
            sort = self.OPTIONS[self.arch.name][option_name][0]

            if sort is None or isinstance(option_value, sort):
                self._options[option_name] = option_value
            else:
                raise ValueError('Value for option "%s" must be of type %s' % (option_name, sort))

        else:
            super(CFGArchOptions, self).__setattr__(option_name, option_value )
