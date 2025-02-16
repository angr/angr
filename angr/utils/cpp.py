from __future__ import annotations


def is_cpp_funcname_ctor(name: str) -> bool:
    """
    Check if a demangled C++ function name is a constructor.

    :param name:    The demangled C++ function name.
    :return:        True if the function name is a constructor, False otherwise.
    """

    # With pydemumble, constructor names look like:
    #    A::A()
    if "::" not in name:
        return False
    parts = name.split("::")
    return bool(len(parts) == 2 and parts[0] and parts[0] + "()" == parts[1])
