from __future__ import annotations

import re

import pyderust

GENERIC_TYPE_PATTERN = re.compile(r"(?:::)?<(?:(?!\sas\s)[^<])*?>")
XXX_AS_YYY_PATTERN = re.compile(r"<(?!impl\s)([^<]+?)\sas\s([^<]+?)>")
IMPL_XXX_AS_YYY_PATTERN = re.compile(r"<impl\s([^<]+?)\sas\s([^<]+?)>")


def demangle(s):
    try:
        return pyderust.demangle(s, include_hash=False)
    except pyderust.DemangleError:
        return s


def normalize(name, monopolize=True, concise=False, use_trait_name=False):
    demangled = demangle(name)
    if monopolize:
        old_len = 0
        while old_len != len(demangled):
            old_len = len(demangled)
            demangled = GENERIC_TYPE_PATTERN.sub("", demangled)
            demangled = XXX_AS_YYY_PATTERN.sub(lambda match: match.groups()[1 if use_trait_name else 0], demangled)
            demangled = IMPL_XXX_AS_YYY_PATTERN.sub(lambda match: match.groups()[1], demangled)
    if concise:
        demangled = demangled.split("::")[-1]
    return demangled
