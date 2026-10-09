from __future__ import annotations

from enum import StrEnum


class Flavors(StrEnum):
    """
    Decompilation flavors; also the keys of per-flavor knowledge (Function prototypes, global variable managers,
    decompilations). Members are strings, so they compare equal to their values.
    """

    # knowledge of code without a flavor of its own (CFG, DWARF, SimProcedures) is stored under the default flavor
    DEFAULT_FLAVOR = "pseudocode"
    RUST_FLAVOR = "rust"
    GO_FLAVOR = "go"
