

class IndirectJumpResolver(object):
    def __init__(self, arch=None, timeless=False):
        self.arch = arch
        self.timeless = timeless

    def filter(self, cfg, addr, func_addr, block):
        """
        Check if this resolution method may be able to resolve the indirect jump or not.

        :param int addr:        Basic block address of this indirect jump.
        :param int func_addr:   Address of the function that this indirect jump belongs to.
        :param block:           The basic block. The type is determined by the backend being used. It's pyvex.IRSB if
                                pyvex is used as the backend.
        :return: True if it is possible for this resolution method to resolve the specific indirect jump, False
                 otherwise.
        :rtype:  bool
        """

        raise NotImplementedError()

    def resolve(self, cfg, addr, func_addr, block):
        """
        Resolve an indirect jump.

        :param cfg:             The CFG analysis object.
        :param int addr:        Basic block address of this indirect jump.
        :param int func_addr:   Address of the function that this indirect jump belongs to.
        :param block:           The basic block. The type is determined by the backend being used. It's pyvex.IRSB if
                                pyvex is used as the backend.
        :return:                A tuple of a boolean indicating whether the resolution is successful or not, and a list
                                of resolved targets (ints).
        :rtype:                 tuple
        """

        raise NotImplementedError()

    def _is_target_valid(self, cfg, target):  # pylint:disable=no-self-use
        """
        Check if the resolved target is valid.

        :param cfg:         The CFG analysis object.
        :param int target:  The target to check.
        :return:            True if the target is valid. False otherwise.
        :rtype:             bool
        """

        if cfg._addr_in_exec_memory_regions(target):
            # the jump target is executable
            return True
        if cfg.project.is_hooked(target):
            # the jump target is hooked
            return True
        return False
