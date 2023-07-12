from typing import Optional, List, Dict

from cle.address_translator import AddressTranslator
from sortedcontainers import SortedDict

from .plugin import KnowledgeBasePlugin


# TODO: Serializable
class Patch:
    def __init__(self, addr, new_bytes, comment: Optional[str] = None):
        self.addr = addr
        self.new_bytes = new_bytes
        self.comment = comment

    def __len__(self):
        return len(self.new_bytes)


class PatchManager(KnowledgeBasePlugin):
    """
    A placeholder-style implementation for a binary patch manager. This class should be significantly changed in the
    future when all data about loaded binary objects are loaded into angr knowledge base from CLE. As of now, it only
    stores byte-level replacements.

    Patches should not overlap, but it's user's responsibility to check for and avoid overlapping patches.
    """

    def __init__(self, kb):
        super().__init__()

        self._patches: Dict[int, Patch] = SortedDict()
        self._kb = kb
        self._patched_entry_state = None

    def add_patch(self, addr, new_bytes, comment: Optional[str] = None):
        self._patches[addr] = Patch(addr, new_bytes, comment=comment)
        self._patched_entry_state = None

    def add_patch_obj(self, patch: Patch):
        self._patches[patch.addr] = patch
        self._patched_entry_state = None

    def remove_patch(self, addr):
        if addr in self._patches:
            del self._patches[addr]
        self._patched_entry_state = None

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
        patches = []
        for patch_addr in self._patches.irange(maximum=addr + size - 1, reverse=True):
            p = self._patches[patch_addr]
            if self.overlap(p.addr, p.addr + len(p), addr, addr + size):
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

    def apply_patches_to_binary(
        self, binary_bytes: Optional[bytes] = None, patches: Optional[List[Patch]] = None
    ) -> bytes:
        if patches is None:
            patches = sorted(list(self._patches.values()), key=lambda x: x.addr)

        if binary_bytes is None:
            with open(self._kb._project.loader.main_object.binary, "rb") as f:
                binary_bytes = f.read()
        for patch in patches:
            # convert addr to file offset
            at = AddressTranslator.from_mva(patch.addr, self._kb._project.loader.main_object)
            file_offset = at.to_raw()

            if file_offset < len(binary_bytes) and file_offset + len(patch.new_bytes) < len(binary_bytes):
                binary_bytes = (
                    binary_bytes[:file_offset] + patch.new_bytes + binary_bytes[file_offset + len(patch.new_bytes) :]
                )

        return binary_bytes

    def apply_patches_to_state(self, state):
        for patch in self._patches.values():
            state.memory.store(patch.addr, patch.new_bytes)

    @property
    def patched_entry_state(self):
        if self._patched_entry_state is None:
            self._patched_entry_state = self._kb._project.factory.entry_state()
            self.apply_patches_to_state(self._patched_entry_state)
        return self._patched_entry_state


KnowledgeBasePlugin.register_default("patches", PatchManager)
