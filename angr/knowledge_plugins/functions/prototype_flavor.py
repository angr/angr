from __future__ import annotations

# flavor key of the C ("pseudocode") decompilation flavor
C_PROTOTYPE_FLAVOR = "c"


def decompilation_flavor_key(decompiler_flavor: str | None) -> str:
    """
    Map a decompiler flavor name to the key under which per-flavor knowledge (Function.prototypes,
    VariableManager.global_managers) is stored. The default decompilation flavor is called "pseudocode" by the
    decompiler but "c" here; every other flavor keeps its name. Keys map to themselves.
    """
    if decompiler_flavor is None or decompiler_flavor == "pseudocode":
        return C_PROTOTYPE_FLAVOR
    return decompiler_flavor


prototype_flavor = decompilation_flavor_key
