
from sortedcontainers import SortedDict

from .plugin import KnowledgeBasePlugin


# TODO: Serializable
class Patch:
    def __init__(self, addr, new_bytes):
        self.addr = addr
        self.new_bytes = new_bytes

    def __len__(self):
        return len(self.new_bytes)


class PatchManager(KnowledgeBasePlugin):
    """
    A placeholder-style implementation for a binary patch manager. This class should be significantly changed in the
    future when all data about loaded binary objects are loaded into angr knowledge base from CLE. As of now, it only
    stores byte-level replacements. Other angr components may choose to use or not use information provided by this
    manager. In other words, it is not transparent.

    Patches should not overlap, but it's user's responsibility to check for and avoid overlapping patches.
    """

    def __init__(self, kb):
        super().__init__()

        self._patches = SortedDict()
        self._kb = kb

    def add_patch(self, addr, new_bytes):
        self._patches[addr] = Patch(addr, new_bytes)

    def remove_patch(self, addr):
        if addr in self._patches:
            del self._patches[addr]

    def patch_addrs(self):
        return self._patches.keys()

    def get_patch(self, addr):
        """
        Get patch at the given address.

        :param int addr:    The address of the patch.
        :return:            The patch if there is one starting at the address, or None if there isn't any.
        :rtype:             Patch or None
        """
        return self._patches.get(addr, None)

    def get_all_patches(self, addr, size):
        """
        Retrieve all patches that cover a region specified by [addr, addr+size).

        :param int addr:    The address of the beginning of the region.
        :param int size:    Size of the region.
        :return:            A list of patches.
        :rtype:             list
        """
        patches = [ ]
        for patch_addr in self._patches.irange(maximum=addr+size-1, reverse=True):
            p = self._patches[patch_addr]
            if self.overlap(p.addr, p.addr + len(p), addr, addr+size):
                patches.append(p)
            else:
                break
        return patches[::-1]

    def keys(self):
        return self._patches.keys()

    def items(self):
        return self._patches.items()

    def values(self):
        return self._patches.values()

    def copy(self):
        o = PatchManager(self._kb)
        o._patches = self._patches.copy()

    @staticmethod
    def overlap(a0, a1, b0, b1):
        return a0 <= b0 < a1 or a0 <= b1 < a1 or b0 <= a0 < b1


KnowledgeBasePlugin.register_default('patches', PatchManager)
