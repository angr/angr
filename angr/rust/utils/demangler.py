import re
import rust_demangler


def _is_rust_hash(s):
    return len(s) == 17 and s.startswith("h") and all(c in "0123456789abcdef" for c in s[1:])


GENERIC_TYPE_PATTERN = re.compile(r"(?:::)?<(?:(?!\sas\s)[^<])*?>")
XXX_AS_YYY_PATTERN = re.compile(r"<(?!impl\s)([^<]+?)\sas\s([^<]+?)>")
IMPL_XXX_AS_YYY_PATTERN = re.compile(r"<impl\s([^<]+?)\sas\s([^<]+?)>")


def demangle(s):
    try:
        demangled = rust_demangler.demangle(s).split("::")
    except:
        return s
    if len(demangled) >= 2 and _is_rust_hash(demangled[-1]):
        demangled = "::".join(demangled[:-1])
    else:
        demangled = "::".join(demangled)
    return demangled


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
