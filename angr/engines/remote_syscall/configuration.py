from typing import Dict


class RemoteSyscallDecision:
    PROXY = 1  # proxy the syscall by a syscall agent
    BYPASS = 2  # do not proxy the syscall through a syscall agent. instead, use a SimProcedure for this syscall
    BOTH = 3  # proxy the syscall through a syscall agent *and* execute the corresponding SimProcedure
    ASK = 4  # ask the user to determine


class RemoteSyscallConfiguration:
    """
    A RemoteSyscallConfiguration specifies SimEngineRemoteSyscall's behavior for each syscall.
    """

    __slots__ = ('default_decision', 'decisions', )

    def __init__(self, default_decision: int, decisions: Dict[str,int]):
        self.default_decision = default_decision
        self.decisions = decisions

    def get_decision(self, syscall_name: str) -> int:
        try:
            decision = self.decisions[syscall_name]
        except KeyError:
            decision = self.default_decision

        if decision == RemoteSyscallDecision.ASK:
            # ask the user what to do
            decision = self.ask_user(syscall_name)

        return decision

    def ask_user(self, syscall_name: str) -> int:
        """
        Ask user for a decision on what to do with this syscall.

        :param syscall_name:    Name of the syscall.
        :return:                The decision.
        """

        while True:
            x = input("Proxying syscall \"%s\" through syscall-agent? ([y]/[n]/[Y]es-to-all/[N]o-to-all) " % syscall_name)
            if x in ('y', 'n', 'Y', 'N'):
                break
            print("Please type 'y', 'n', 'Y', or 'N'.")

        if x == 'Y':
            # yes to all
            self.decisions[syscall_name] = RemoteSyscallDecision.PROXY
        elif x == 'N':
            # no to all
            self.decisions[syscall_name] = RemoteSyscallDecision.BYPASS

        x = x.lower()
        return RemoteSyscallDecision.PROXY if x == 'y' else RemoteSyscallDecision.BYPASS


D = RemoteSyscallDecision
DEFAULT_CONFIG = RemoteSyscallConfiguration(
    D.PROXY,
    {
        'mmap': D.BYPASS,
        'munmap': D.BYPASS,
        'brk': D.BYPASS,
        'open': D.ASK,
        'write': D.BYPASS,
        'read': D.BYPASS,
        'close': D.ASK,
        'dup': D.BYPASS,
        'dup2': D.BYPASS,
        'dup3': D.BYPASS,
        'exit': D.BYPASS,
        'exit_group': D.BYPASS,
        # mips-n32, mips-o32, mips-n64
        'set_thread_area': D.BYPASS
    }
)
