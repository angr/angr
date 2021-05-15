
class Pattern:

    __slots__ = ('arch', 'pattern', 'is_function', 'function_name', 'is_thumb_mode', )

    def __init__(self, arch: str, pattern: bytes, is_function: bool, function_name: str=None, is_thumb_mode: bool=None):
        self.arch = arch  # not really used
        self.pattern = pattern
        self.is_function = is_function
        self.function_name = function_name
        self.is_thumb_mode = is_thumb_mode

    def __repr__(self):
        return "<Pattern %s: %s>" % (self.arch, self.function_name)


#
# ARM Thumb mode
#

__gnu_thumb1_case_si = Pattern(
    "ARM",
    b"\x03\xb4\x71\x46\x02\x31\x89\x08\x80\x00\x89\x00\x08\x58\x40\x18\x86\x46\x03\xbc\xf7\x46",
    True,
    function_name="__gnu_thumb1_case_si",
    is_thumb_mode=True,
)

__gnu_thumb1_case_uqi = Pattern(
    "ARM",
    b"\x02\xb4\x71\x46\x49\x08\x49\x00\x09\x5c\x49\x00\x8e\x44\x02\xbc\x70\x47",
    True,
    function_name="__gnu_thumb1_case_uqi",
    is_thumb_mode=True,
)

__gnu_thumb1_case_sqi = Pattern(
    "ARM",
    b"\x02\xb4\x71\x46\x49\x08\x49\x00\x09\x56\x49\x00\x8e\x44\x02\xbc\x70\x47",
    True,
    function_name="__gnu_thumb1_case_sqi",
    is_thumb_mode=True,
)

__gnu_thumb1_case_shi = Pattern(
    "ARM",
    b"\x03\xb4\x71\x46\x49\x08\x40\x00\x49\x00\x09\x5e\x49\x00\x8e\x44\x03\xbc\x70\x47",
    True,
    function_name="__gnu_thumb1_case_shi",
    is_thumb_mode=True,
)

__gnu_thumb1_case_uhi = Pattern(
    "ARM",
    b"\x03\xb4\x71\x46\x49\x08\x40\x00\x49\x00\x09\x5a\x49\x00\x8e\x44\x03\xbc\x70\x47",
    True,
    function_name="__gnu_thumb1_case_uhi",
    is_thumb_mode=True,
)


PATTERNS = {
    "ARMEL": [
        __gnu_thumb1_case_si,
        __gnu_thumb1_case_uqi,
        __gnu_thumb1_case_sqi,
        __gnu_thumb1_case_shi,
        __gnu_thumb1_case_uhi,
    ],
    "ARMHF": [
        __gnu_thumb1_case_si,
        __gnu_thumb1_case_uqi,
        __gnu_thumb1_case_sqi,
        __gnu_thumb1_case_shi,
        __gnu_thumb1_case_uhi,
    ],
    "CortexM": [
        __gnu_thumb1_case_si,
        __gnu_thumb1_case_uqi,
        __gnu_thumb1_case_sqi,
        __gnu_thumb1_case_shi,
        __gnu_thumb1_case_uhi,
    ],
}
