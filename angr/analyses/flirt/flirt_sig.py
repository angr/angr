from __future__ import annotations
import struct
import zlib
from io import BytesIO

from angr.errors import AngrError
from .consts import FlirtParseFlag, FlirtFeatureFlag, FlirtFunctionFlag
from .flirt_utils import read_max_2_bytes, read_multiple_bytes
from .flirt_function import FlirtFunction
from .flirt_module import FlirtModule
from .flirt_node import FlirtNode


class FlirtSignatureError(AngrError):
    """
    Describes errors related to FLIRT signatures, especially parsing.
    """


class FlirtSignature:
    """
    This class describes a FLIRT signature without any internal data that is only available after parsing.
    """

    def __init__(
        self,
        arch: str,
        platform: str,
        sig_name: str,
        sig_path: str,
        unique_strings: set[str] | None = None,
        compiler: str | None = None,
        compiler_version: str | None = None,
        os_name: str | None = None,
        os_version: str | None = None,
    ):
        self.arch = arch
        self.platform = platform
        self.sig_name = sig_name
        self.sig_path = sig_path
        self.unique_strings = unique_strings
        self.compiler = compiler
        self.compiler_version = compiler_version
        self.os_name = os_name
        self.os_version = os_version

    def __repr__(self):
        if self.os_name:
            if self.os_version:
                return f"<{self.sig_name}@{self.arch}-{self.os_name}-{self.os_version}>"
            return f"<{self.sig_name}@{self.arch}-{self.os_name}>"
        return f"<{self.sig_name}@{self.arch}-{self.platform}>"


class FlirtSignatureParsed:
    """
    Describes a FLIRT signature file after parsing.
    """

    __slots__ = (
        "app_types",
        "arch",
        "crc",
        "ctype",
        "ctypes_crc",
        "features",
        "file_types",
        "libname",
        "nfuncs",
        "os_types",
        "pattern_size",
        "root",
        "version",
    )

    def __init__(
        self,
        version: int,
        arch: int,
        file_types: int,
        os_types: int,
        app_types: int,
        features: int,
        crc: int,
        ctype: int,
        ctypes_crc: int,
        nfuncs: int | None,
        pattern_size: int | None,
        libname: str,
        root: FlirtNode | None,
    ):
        self.version = version
        self.arch = arch
        self.file_types = file_types
        self.os_types = os_types
        self.app_types = app_types
        self.features = features
        self.crc = crc
        self.ctype = ctype
        self.ctypes_crc = ctypes_crc
        self.nfuncs = nfuncs
        self.pattern_size = pattern_size
        self.libname = libname
        self.root = root

    def parse_tree(self, file_obj, root: bool = False) -> FlirtNode:
        """
        Parse a FLIRT function tree.
        """

        if not root:
            length = file_obj.read(1)[0]
            variant_mask = self.parse_variant_mask(file_obj, length)
            pattern = self.parse_node(file_obj, length, variant_mask)
        else:
            length = 0
            pattern = []

        node_count = read_multiple_bytes(file_obj)
        if node_count > 0:
            # non-leaf; load its child nodes
            nodes: list[FlirtNode] = [None] * node_count  # type: ignore
            for i in range(node_count):
                nn = self.parse_tree(file_obj)
                nodes[i] = nn
            return FlirtNode(nodes, [], length, pattern)
        # leaf
        modules = self.parse_modules(file_obj)
        return FlirtNode([], modules, length, pattern)

    def parse_public_function(self, file_obj, offset: int) -> tuple[FlirtFunction, int, int]:
        off = read_multiple_bytes(file_obj) if self.version >= 9 else read_max_2_bytes(file_obj)
        off += offset

        local = False  # is it a local function?
        collision = False  # is it an unresolved collision?

        flags = file_obj.read(1)[0]
        if flags < 0x20:
            local = bool(flags & FlirtFunctionFlag.FUNCTION_LOCAL)
            collision = bool(flags & FlirtFunctionFlag.FUNCTION_UNRESOLVED_COLLISION)
            next_byte = file_obj.read(1)[0]
        else:
            next_byte = flags

        name_lst = []
        name_end = False  # in case the function name is too long...
        for _ in range(1024):  # max length of a function name
            if next_byte < 0x20:
                name_end = True
                break
            name_lst.append(next_byte)
            next_byte = file_obj.read(1)[0]

        name = bytes(name_lst).decode("utf-8")
        if not name_end:
            name = name + "..."
        return FlirtFunction(name, off, local, collision), off, next_byte

    def parse_referenced_functions(self, file_obj) -> list[FlirtFunction]:
        func_count = file_obj.read(1)[0] if self.version >= 8 else 1
        lst = []
        for _ in range(func_count):
            off = read_multiple_bytes(file_obj) if self.version >= 9 else read_max_2_bytes(file_obj)
            name_len = file_obj.read(1)[0]
            if name_len == 0:
                name_len = read_multiple_bytes(file_obj)
            if name_len > 1024:
                raise FlirtSignatureError(f"Function name too long: {name_len}")
            name_bytes = file_obj.read(name_len)
            if len(name_bytes) < name_len:
                raise FlirtSignatureError("Unexpected EOF")
            name = name_bytes.decode("utf-8").rstrip("\x00")
            lst.append(FlirtFunction(name, off, False, False))
        return lst

    def parse_tail_bytes(self, file_obj) -> list[tuple[int, int]]:
        bytes_count = file_obj.read(1)[0] if self.version >= 8 else 1
        lst = []
        for _ in range(bytes_count):
            off = read_multiple_bytes(file_obj) if self.version >= 9 else read_max_2_bytes(file_obj)
            value = file_obj.read(1)[0]
            lst.append((off, value))
        return lst

    def parse_modules(self, file_obj) -> list[FlirtModule]:
        modules = []
        while True:
            crc_len = file_obj.read(1)[0]
            crc = struct.unpack(">H", file_obj.read(2))[0]

            while True:
                # parse all modules with the same CRC
                module, flags = self.parse_module(file_obj)
                module.crc_len = crc_len
                module.crc = crc
                modules.append(module)
                if flags & FlirtParseFlag.PARSE_MORE_MODULES_WITH_SAME_CRC == 0:
                    break

            # same crc length but different crc
            if flags & FlirtParseFlag.PARSE_MORE_MODULES == 0:
                break
        return modules

    def parse_module(self, file_obj) -> tuple[FlirtModule, int]:
        length = read_multiple_bytes(file_obj) if self.version >= 9 else read_max_2_bytes(file_obj)
        pub_funcs = []
        off = 0
        while True:
            func, off, flags = self.parse_public_function(file_obj, off)
            pub_funcs.append(func)
            if flags & FlirtParseFlag.PARSE_MORE_PUBLIC_NAMES == 0:
                break

        tail_bytes: list[tuple[int, int]] = []
        if flags & FlirtParseFlag.PARSE_READ_TAIL_BYTES:
            tail_bytes = self.parse_tail_bytes(file_obj)

        ref_funcs = []
        if flags & FlirtParseFlag.PARSE_READ_REFERENCED_FUNCTIONS:
            ref_funcs = self.parse_referenced_functions(file_obj)

        return (
            FlirtModule(
                length,
                0,  # back-filled in its caller
                0,  # back-filled in its caller
                pub_funcs,
                ref_funcs,
                tail_bytes,
            ),
            flags,
        )

    @staticmethod
    def parse_variant_mask(file_obj, length: int) -> int:
        if length < 0x10:
            return read_max_2_bytes(file_obj)
        if length <= 0x20:
            return read_multiple_bytes(file_obj)
        if length <= 0x40:
            return (read_multiple_bytes(file_obj) << 32) | read_multiple_bytes(file_obj)
        raise FlirtSignatureError(f"Unexpected variant mask length: {length}")

    @staticmethod
    def is_bit_set_be(mask: int, mask_len: int, bit_offset: int) -> bool:
        assert mask_len > bit_offset
        return mask & (1 << (mask_len - bit_offset - 1)) != 0

    @staticmethod
    def parse_node(file_obj, length: int, variant_mask: int) -> list[int]:
        pattern = [-1] * length
        for i in range(length):
            if not FlirtSignatureParsed.is_bit_set_be(variant_mask, length, i):
                pattern[i] = file_obj.read(1)[0]
        return pattern

    @classmethod
    def parse(cls, file_obj) -> FlirtSignatureParsed:
        """
        Parse a FLIRT signature file.

        The following struct definitions come from radare2

        // FLIRT v5+
        ut8 magic[6];
        ut8 version;
        ut8 arch;
        ut32 file_types;
        ut16 os_types;
        ut16 app_types;
        ut16 features;
        ut16 old_n_functions;
        ut16 crc16;
        ut8 ctype[12];
        ut8 library_name_len;
        ut16 ctypes_crc16;

        // FLIRT v6+
        ut32 nfuncs;

        // FLIRT v8+
        ut16 pattern_size;

        // FLIRT v10
        ut16 unknown;
        """

        struct_str = "<6s B B I H H H H H 12s B H".replace(" ", "")
        sz = struct.calcsize(struct_str)
        header_bytes = file_obj.read(sz)
        if len(header_bytes) != sz:
            raise FlirtSignatureError
        unpacked = struct.unpack(struct_str, header_bytes)

        # sanity check
        if unpacked[0] != b"IDASGN":
            raise FlirtSignatureError("Unexpected magic bytes")

        version = unpacked[1]
        if version < 5:
            raise FlirtSignatureError("Unsupported FLIRT signature version")

        if version >= 6:
            # nfuncs
            data = file_obj.read(4)
            if len(data) != 4:
                raise FlirtSignatureError("Unexpected EOF")
            nfuncs = struct.unpack("<I", data)[0]
        else:
            nfuncs = None
        if version >= 8:
            # pattern_size
            data = file_obj.read(2)
            if len(data) != 2:
                raise FlirtSignatureError("Unexpected EOF")
            pattern_size = struct.unpack("<H", data)[0]
        else:
            pattern_size = None

        if version >= 10:
            # unknown
            data = file_obj.read(2)
            if len(data) != 2:
                raise FlirtSignatureError("Unexpected EOF")

        libname_len = unpacked[10]
        libname = file_obj.read(libname_len).decode("utf-8")

        obj = cls(
            version=version,
            arch=unpacked[2],
            file_types=unpacked[3],
            os_types=unpacked[4],
            app_types=unpacked[5],
            features=unpacked[6],
            crc=unpacked[7],
            ctype=unpacked[8],
            ctypes_crc=unpacked[11],
            nfuncs=nfuncs,
            pattern_size=pattern_size,
            libname=libname,
            root=None,
        )

        # is it compressed?
        if obj.features & FlirtFeatureFlag.FEATURE_COMPRESSED:
            data = file_obj.read()
            decompressed = BytesIO(zlib.decompress(data))
            file_obj = decompressed

        root = obj.parse_tree(file_obj, root=True)

        obj.root = root
        return obj
