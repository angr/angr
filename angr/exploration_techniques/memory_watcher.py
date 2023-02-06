from . import ExplorationTechnique
import psutil


class MemoryWatcher(ExplorationTechnique):
    """Memory Watcher

    Args:
        min_memory (int,optional): Minimum amount of free memory in MB before
                    stopping execution (default: 95% memory use)
        memory_stash (str, optional): What to call the low memory stash
                    (default: 'lowmem')

    At each step, keep an eye on how much memory is left on the system. Stash
    off states to effectively stop execution if we're below a given threshold.
    """

    def __init__(self, min_memory=512, memory_stash="lowmem"):
        super().__init__()

        if min_memory is not None:
            self.min_memory = 1024 * 1024 * min_memory

        else:
            self.min_memory = int(psutil.virtual_memory().total * 0.05)

        self.memory_stash = memory_stash

    def setup(self, simgr):
        if self.memory_stash not in simgr.stashes:
            simgr.stashes[self.memory_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        if psutil.virtual_memory().available <= self.min_memory:
            simgr.move(from_stash="active", to_stash=self.memory_stash)

        else:
            simgr = simgr.step(stash=stash, **kwargs)

        return simgr
