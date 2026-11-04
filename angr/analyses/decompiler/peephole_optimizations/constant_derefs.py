from __future__ import annotations

from cle.backends import Blob, Hex

from angr.ailment.expression import Const, Load
from angr.utils.loader import is_in_readonly_section

from .base import PeepholeOptimizationExprBase


class ConstantDereferences(PeepholeOptimizationExprBase):
    """
    Dereferences constant memory loads from read-only memory regions.
    """

    __slots__ = ()

    NAME = "Dereference constant references"
    expr_classes = (Load,)
    # treat every byte of a blob as constant
    DEREF_BLOBS = True

    def optimize(self, expr: Load, **kwargs):
        if isinstance(expr.addr, Const) and expr.size in {1, 2, 4, 8, 10, 16, 32, 64, 128, 256}:
            assert self.project is not None
            # is it loading from a read-only section?
            sec = self.project.loader.find_section_containing(expr.addr.value)
            if sec is not None and self._is_constant_memory(sec, expr.addr.value, expr.size):
                # do we know the value that it's reading?
                try:
                    if expr.size == 10:
                        # 10-byte x87 extended precision -- read raw bytes
                        raw = self.project.loader.memory.load(expr.addr.value, 10)
                        val = int.from_bytes(raw, "little")
                    else:
                        val = self.project.loader.memory.unpack_word(expr.addr.value, size=expr.size)
                except KeyError:
                    return None
                if "got" in sec.name and val == 0:
                    return None

                tags = dict(expr.tags)
                if expr.tags.get("data_type", "").startswith("Ity_F"):
                    import struct

                    if expr.bits == 64:
                        val = struct.unpack("d", struct.pack("Q", val))[0]
                    elif expr.bits == 32:
                        val = struct.unpack("f", struct.pack("I", val))[0]

                if expr.tags.get("long_double_load"):
                    tags["display_hint"] = "double"

                return Const(self.manager.next_atom(), val, expr.bits, **tags, deref_src_addr=expr.addr.value)

            # is it loading from a blob?
            obj = self.project.loader.find_object_containing(expr.addr.value) if self.DEREF_BLOBS else None
            if obj is not None and isinstance(obj, (Blob, Hex)):
                # do we know the value that it's reading?
                try:
                    val = self.project.loader.memory.unpack_word(expr.addr.value, size=self.project.arch.bytes)
                except KeyError:
                    return None

                return Const(self.manager.next_atom(), val, expr.bits, **expr.tags, deref_src_addr=expr.addr.value)

        # FIXME: Handle floating point here

        return None

    def _is_constant_memory(self, sec, addr: int, size: int) -> bool:  # pylint:disable=unused-argument
        return sec.is_readable and ("got" in sec.name or is_in_readonly_section(self.project, addr))


class ReadOnlyConstantDereferences(ConstantDereferences):
    """
    Dereferences constant memory loads from read-only sections and the VM's byte code regions only. A blob may be a
    snapshot of writable memory, such as the process dump a devirtualized VM body is decompiled from.
    """

    __slots__ = ()

    DEREF_BLOBS = False

    def _is_constant_memory(self, sec, addr: int, size: int) -> bool:
        # a VM's byte code sits in a writable section; it is constant on the image pages the devirtualized function
        # never stores to (vex_concrete_fold reads the image under the same assumption)
        regions = getattr(self.project, "byte_code_regions", None) or ()
        written = getattr(self.project, "vm_written_image_pages", None)
        if (
            written is not None
            and any(lo <= addr and addr + size <= hi for lo, hi in regions)
            and not any(page in written for page in range(addr & ~0xFFF, addr + size, 0x1000))
        ):
            return True
        return super()._is_constant_memory(sec, addr, size)
