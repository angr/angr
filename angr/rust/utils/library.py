import re


def _is_control(c):
    return ord(c) < 32 or ord(c) == 127


def _fmt(inner, elements):
    result = []
    for element in range(elements):
        rest = inner
        while rest[0].isdigit():
            rest = rest[1:]
        i = int(inner[: len(inner) - len(rest)])
        inner = rest[i:]
        rest = rest[:i]

        if element != 0:
            result.append("::")
        if rest.startswith("_$"):
            rest = rest[1:]
        while True:
            if rest.startswith("."):
                if len(rest) > 1 and rest[1] == ".":
                    result.append("::")
                    rest = rest[2:]
                else:
                    result.append(".")
                    rest = rest[1:]
            elif rest.startswith("$"):
                if "$" in rest[1:]:
                    escape, rest = rest[1:].split("$", 1)
                else:
                    break

                unescaped = {"SP": "@", "BP": "*", "RF": "&", "LT": "<", "GT": ">", "LP": "(", "RP": ")", "C": ","}.get(
                    escape, None
                )

                if unescaped is None and escape.startswith("u"):
                    digits = escape[1:]
                    if all(c in "0123456789abcdef" for c in digits):
                        c = chr(int(digits, 16))
                        if not _is_control(c):
                            result.append(c)
                            continue
                if unescaped:
                    result.append(unescaped)
                else:
                    break
            else:
                idx = min((rest.find(c) for c in "$." if c in rest), default=len(rest))
                result.append(rest[:idx])
                rest = rest[idx:]
                if not rest:
                    break
        result.append(rest)
    return "".join(result)


def _is_rust_hash(s):
    return s.startswith("h") and all(c in "0123456789abcdef" for c in s[1:])


GENERIC_TYPE_PATTERN = re.compile(r"(?:::)?<(?:(?!\sas\s)[^<])*?>")
XXX_AS_YYY_PATTERN = re.compile(r"<(?!impl\s)([^<]+?)\sas\s([^<]+?)>")
IMPL_XXX_AS_YYY_PATTERN = re.compile(r"<impl\s([^<]+?)\sas\s([^<]+?)>")


def demangle(s):
    if s.startswith("_ZN"):
        inner = s[3:]
    elif s.startswith("ZN"):
        inner = s[2:]
    elif s.startswith("__ZN"):
        inner = s[4:]
    else:
        return s

    if any(c for c in inner if ord(c) & 0x80):
        return s

    elements = 0
    chars = iter(inner)
    c = next(chars, None)
    while c and c != "E":
        if not c.isdigit():
            return s
        length = 0
        while c.isdigit():
            length = length * 10 + int(c)
            c = next(chars, None)
        for _ in range(length):
            c = next(chars, None)
        elements += 1
    demangled = _fmt(inner, elements).split("::")
    if len(demangled) >= 2 and _is_rust_hash(demangled[-1]):
        demangled = "::".join(demangled[:-1])
    else:
        demangled = "::".join(demangled)
    return demangled


def normalize(name, remove_polymorphism=True, concise=False):
    demangled = demangle(name)
    if remove_polymorphism:
        old_len = 0
        while old_len != len(demangled):
            old_len = len(demangled)
            demangled = GENERIC_TYPE_PATTERN.sub("", demangled)
            demangled = XXX_AS_YYY_PATTERN.sub(lambda match: match.groups()[0], demangled)
            demangled = IMPL_XXX_AS_YYY_PATTERN.sub(lambda match: match.groups()[1], demangled)
    if concise:
        demangled = demangled.split("::")[-1]
    return demangled
