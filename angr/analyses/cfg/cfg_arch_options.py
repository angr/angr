from __future__ import annotations


class CFGArchOptions:
    """
    Stores architecture-specific options and settings, as well as the detailed explanation of those options and
    settings.

    Suppose `ao` is the CFGArchOptions object, and there is an option called `ret_jumpkind_heuristics`, you can access
    it by `ao.ret_jumpkind_heuristics` and set its value via `ao.ret_jumpkind_heuristics = True`

    :ivar dict OPTIONS: A dict of all default options for different architectures.
    :ivar archinfo.Arch arch: The architecture object.
    :ivar dict _options: Values of all CFG options that are specific to the current architecture.
    """

    # option name: (option value type, default option value)

    OPTIONS = {
        "ARMEL": {
            # Whether to perform some simple heuristics to detect returns that are incorrectly labeled as boring
            # branches by VEX
            "ret_jumpkind_heuristics": (bool, True),
            # Whether to switch between ARM mode and THUMB mode when VEX fails to decode a block
            "switch_mode_on_nodecode": (bool, True),
            # Whether we should use byte-based pattern-matching to identify ifuncs
            "pattern_match_ifuncs": (bool, True),
        },
        "ARMHF": {
            "ret_jumpkind_heuristics": (bool, True),
            "switch_mode_on_nodecode": (bool, True),
            "pattern_match_ifuncs": (bool, True),
        },
        "ARMCortexM": {
            "ret_jumpkind_heuristics": (bool, True),
            "switch_mode_on_nodecode": (bool, False),
            "pattern_match_ifuncs": (bool, True),
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
            for k, (_, value) in self.OPTIONS[self.arch.name].items():
                self._options[k] = value

        # make sure options are valid
        for k in options:
            if self.arch.name not in self.OPTIONS or k not in self.OPTIONS[self.arch.name]:
                raise KeyError(f'Architecture {self.arch.name} does not support arch-specific option "{k}".')

        for k, v in options.items():
            self.__setattr__(k, v)

    def __getattr__(self, option_name):
        if option_name in self._options:
            return self._options[option_name]

        return self.__getattribute__(option_name)

    def __setattr__(self, option_name, option_value):
        if option_name in self._options:
            # Type checking
            sort = self.OPTIONS[self.arch.name][option_name][0]

            if sort is None or isinstance(option_value, sort):
                self._options[option_name] = option_value
            else:
                raise ValueError(f'Value for option "{option_name}" must be of type {sort}')

        else:
            super().__setattr__(option_name, option_value)
