from __future__ import annotations

import re
from functools import lru_cache

import pydemumble


def _is_rust_hash(s):
    return len(s) == 17 and s.startswith("h") and all(c in "0123456789abcdef" for c in s[1:])


def _looks_like_rust(s):
    # Rust manglings are either v0 ("_R...") or the legacy nested-Itanium form
    # ("_ZN...E"). Strip one optional leading underscore (macOS). General C++
    # ("_Z3fooi"), MSVC ("?..."), and plain names are left untouched: pydemumble
    # would happily demangle those, but this wrapper is Rust-only.
    body = s[1:] if s.startswith("__") else s
    return body.startswith(("_R", "_ZN"))


GENERIC_TYPE_PATTERN = re.compile(r"(?:::)?<(?:(?!\sas\s)[^<])*?>")
XXX_AS_YYY_PATTERN = re.compile(r"<(?!impl\s)([^<]+?)\sas\s([^<]+?)>")
IMPL_XXX_AS_YYY_PATTERN = re.compile(r"<impl\s([^<]+?)\sas\s([^<]+?)>")

# demumble renders trailing symbol suffixes (e.g. ".llvm.1234", ".0") as " (.suffix)"
TRAILING_SUFFIX_PATTERN = re.compile(r" \((\.[^)]+)\)$")


@lru_cache(maxsize=4096)
def demangle(s):
    if not _looks_like_rust(s):
        return s
    demangled = pydemumble.demangle(s)
    if not demangled:
        return s
    suffix = ""
    match = TRAILING_SUFFIX_PATTERN.search(demangled)
    if match is not None:
        demangled = demangled[: match.start()]
        if not match.group(1).startswith(".llvm."):
            suffix = match.group(1)
    parts = demangled.split("::")
    if len(parts) >= 2 and _is_rust_hash(parts[-1]):
        demangled = "::".join(parts[:-1])
    return demangled + suffix


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
