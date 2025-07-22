from __future__ import annotations

from .decompilation_note import DecompilationNote


class DeobfuscatedString:
    """
    Represents a deobfuscated string.
    """

    __slots__ = ("ref_addr", "type", "value")

    def __init__(self, value: bytes, obf_type: str, ref_addr: int | None = None):
        self.value = value
        self.type = obf_type
        self.ref_addr = ref_addr

    def __repr__(self):
        return (
            f"<DeobfuscatedString Type{self.type} value={self.value!r} ref={self.ref_addr:#x}>"
            if self.ref_addr is not None
            else f"<DeobfuscatedString Type{self.type} value={self.value!r}>"
        )

    def __str__(self):
        return repr(self.value)


class DeobfuscatedStringsNote(DecompilationNote):
    """
    Represents a decompilation note that describes obfuscated strings found during decompilation.
    """

    def __init__(self, key: str = "deobfuscated_strings", name: str = "Deobfuscated Strings"):
        super().__init__(key, name, None)

        self.strings: dict[int, DeobfuscatedString] = {}

    def add_string(self, obf_type: str, value: bytes, *, ref_addr: int):
        """
        Add a deobfuscated string to the note.

        :param obf_type: The type of obfuscation (e.g., "1", "2").
        :param value: The deobfuscated string value.
        :param ref_addr: The address where this string is referenced, if applicable.
        """
        deobf_str = DeobfuscatedString(value, obf_type, ref_addr=ref_addr)
        self.strings[ref_addr] = deobf_str

    def __str__(self):
        lines = ["Obfuscated strings are found in decompilation and have been deobfuscated:"]
        for addr in sorted(self.strings):
            deobf_str = self.strings[addr]
            lines.append(f"  Type {deobf_str.type} @ {deobf_str.ref_addr:#x}: {deobf_str.value!r}")

        return "\n".join(lines)
