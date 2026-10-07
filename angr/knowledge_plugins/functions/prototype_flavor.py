from __future__ import annotations

# prototype-flavor key of the C ("pseudocode") decompilation flavor
C_PROTOTYPE_FLAVOR = "c"


def prototype_flavor(decompiler_flavor: str | None) -> str:
    """
    Map a decompiler flavor name to the key of Function.prototypes. The default decompilation flavor is called
    "pseudocode" by the decompiler but "c" here; every other flavor keeps its name.
    """
    if decompiler_flavor is None or decompiler_flavor == "pseudocode":
        return C_PROTOTYPE_FLAVOR
    return decompiler_flavor
