from __future__ import annotations


class XRefType:
    Offset = 0
    Read = 1
    Write = 2

    @staticmethod
    def to_string(ty):
        s = {
            XRefType.Offset: "offset",
            XRefType.Read: "read",
            XRefType.Write: "write",
        }
        return s.get(ty, "unknown")
