from __future__ import annotations

from archinfo.arch_arm import is_arm_arch


class CFGArchOptions:
    """
    Stores architecture-specific options and settings, as well as the detailed explanation of those options and
    settings.

    Suppose `ao` is the CFGArchOptions object, and there is an option called `ret_jumpkind_heuristics`, you can access
    it by `ao.ret_jumpkind_heuristics` and set its value via `ao.ret_jumpkind_heuristics = True`

    :ivar dict OPTIONS: A dict of all default options for different architectures.
    :ivar dict ARM_DEFAULT_OPTIONS: Defaults for an ARM architecture that OPTIONS does not name.
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
            # Do we consider ARM-mode code at all
            "has_arm_code": (bool, True),
        },
        "ARMHF": {
            "ret_jumpkind_heuristics": (bool, True),
            "switch_mode_on_nodecode": (bool, True),
            "pattern_match_ifuncs": (bool, True),
            "has_arm_code": (bool, True),
        },
        "ARMCortexM": {
            "ret_jumpkind_heuristics": (bool, True),
            "switch_mode_on_nodecode": (bool, False),
            "pattern_match_ifuncs": (bool, True),
            "has_arm_code": (bool, False),
        },
    }

    # Defaults for an ARM architecture OPTIONS does not name, which today means the p-code ARM languages. The
    # p-code lifter gates its THUMB normalization on ArchARM, so an address there carries no mode: the options
    # that only apply to THUMB code are off, and every address stays a candidate for ARM-mode code.
    ARM_DEFAULT_OPTIONS = {
        "ret_jumpkind_heuristics": (bool, True),
        "switch_mode_on_nodecode": (bool, False),
        "pattern_match_ifuncs": (bool, False),
        "has_arm_code": (bool, True),
    }

    arch = None
    _options = {}
    _supported_options = {}

    def __init__(self, arch, **options):
        """
        Constructor.

        :param archinfo.Arch arch: The architecture instance.
        :param dict options: Architecture-specific options, which will be used to initialize this object.
        """

        self.arch = arch

        if arch.name in self.OPTIONS:
            self._supported_options = self.OPTIONS[arch.name]
        elif is_arm_arch(arch):
            self._supported_options = self.ARM_DEFAULT_OPTIONS
        else:
            self._supported_options = {}

        self._options = {k: value for k, (_, value) in self._supported_options.items()}

        # make sure options are valid
        for k in options:
            if k not in self._supported_options:
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
            sort = self._supported_options[option_name][0]

            if sort is None or isinstance(option_value, sort):
                self._options[option_name] = option_value
            else:
                raise ValueError(f'Value for option "{option_name}" must be of type {sort}')

        else:
            super().__setattr__(option_name, option_value)

    def __getitem__(self, option_name: str):
        return self._options[option_name]

    def __contains__(self, option_name: str) -> bool:
        return option_name in self._options
