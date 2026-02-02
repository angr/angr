import logging
import re
from collections import defaultdict
from pathlib import Path
import json

from angr.rust.sim_type import (
    RustSimTypeSize,
    RustSimStruct,
    RustSimTypeInt,
    RustSimEnum,
    EnumVariant,
    RustSimTypeBottom,
    RustSimTypeReference,
    RustSimTypeArray,
    RustSimTypeOption,
    RustSimTypeResult,
    RustSimTypeFunction,
)
from angr.rust.utils.demangler import demangle
from angr.calling_conventions import default_cc
from angr.rust.definitions.commit_versions import COMMIT_VERSIONS
from angr.analyses import Analysis, AnalysesHub
from angr.knowledge_plugins.cfg import MemoryDataSort

l = logging.getLogger(__name__)


class RustVersionIdentifier:

    def __init__(self, project):
        self.cfg = project.kb.cfgs.get_most_accurate()

    def _get_all_strings(self):
        lst = []
        if self.cfg is None:
            return lst
        for v in self.cfg.memory_data.values():
            if v.sort in {MemoryDataSort.String, MemoryDataSort.UnicodeString}:
                try:
                    lst.append(v.content.decode())
                except UnicodeDecodeError:
                    pass
        return lst

    def _extract_rustc_version(self):
        lines = self._get_all_strings()

        # 1. Try to find /rustc/<commit_hash>/
        rustc_commit_pattern = re.compile(r"/rustc/([0-9a-f]{40})[/\\]")
        for line in lines:
            match = rustc_commit_pattern.search(line)
            if match:
                commit_hash = match.group(1)
                l.debug(f"Found rustc commit hash: {commit_hash}")

                version = COMMIT_VERSIONS.get(commit_hash, None)
                if version:
                    return version
                return None

        # 2. Fallback: Try to find version string like rustc 1.46.0 or rust-1.46.0
        version_patterns = [
            re.compile(r"rustc\s+([0-9]+\.[0-9]+\.[0-9]+)"),
            re.compile(r"rust-([0-9]+\.[0-9]+\.[0-9]+)"),
        ]
        for pattern in version_patterns:
            for line in lines:
                match = pattern.search(line)
                if match:
                    return match.group(1)
        return None

    def identify_rust_version(self):
        return self._extract_rustc_version() or "1.88.0"


class TypeDBLoader(Analysis):
    def __init__(self):
        self._struct_db = None
        self._prototype_db = None
        self._pending_types = set()

        self._analyze()

    @property
    def _structs(self):
        return self.project.kb.known_structs.known_struct_types

    def _apply_patches(self):
        argument_ty = self.project.kb.known_structs["core::fmt::rt::Argument"]
        if argument_ty and "ty" in argument_ty.fields:
            argument_enum = self.project.kb.known_structs["core::fmt::rt::ArgumentType"]
            if argument_enum and argument_enum.get_variant_by_name("Placeholder"):
                placeholder_variant = argument_enum.get_variant_by_name("Placeholder")
                if placeholder_variant:
                    new_argument_ty = placeholder_variant.as_struct_ty()
                    new_argument_ty.name = "core::fmt::rt::Argument"
                    self.project.kb.known_structs["core::fmt::rt::Argument"] = new_argument_ty

    def _parse_Pointer(self, data):
        return RustSimTypeReference(self._parse_type(data["pts_to"]) or RustSimTypeBottom()).with_arch(
            self.project.arch
        )

    def _parse_Primitive(self, data):
        name = data["name"]
        rust_primitive_types = {
            # Integer types
            "i8": RustSimTypeInt(8, True),
            "i16": RustSimTypeInt(16, True),
            "i32": RustSimTypeInt(32, True),
            "i64": RustSimTypeInt(64, True),
            "i128": RustSimTypeInt(128, True),
            "isize": RustSimTypeSize(True),
            "u8": RustSimTypeInt(8, False),
            "u16": RustSimTypeInt(16, False),
            "u32": RustSimTypeInt(32, False),
            "u64": RustSimTypeInt(64, False),
            "u128": RustSimTypeInt(128, False),
            "usize": RustSimTypeSize(False),
            # Floating-point types
            "f32": None,
            "f64": None,
            # Boolean
            "bool": RustSimTypeInt(8, False),
            # Character
            "char": RustSimTypeInt(8, False),
        }
        result = rust_primitive_types.get(name, RustSimTypeInt(data["size"] * self.project.arch.byte_width, False))
        if result is not None:
            return result.with_arch(self.project.arch)
        return None

    def _parse_Struct(self, data):
        name = data["name"]
        if name in self._structs:
            return self._structs[name]
        if name in self._pending_types:
            return RustSimTypeBottom()
        result = None
        fields_data = data["fields"]
        # If fields_data is None, it means the struct is referenced and defined elsewhere
        if fields_data is None:
            actual_data = self._struct_db.get(name, None)
            if actual_data:
                result = self._parse_Struct(actual_data)
        else:
            self._pending_types.add(name)
            fields = {}
            for field_name, field_data in fields_data.values():
                fields[field_name] = self._parse_type(field_data)
            if None not in fields.values():
                result = RustSimStruct(fields=fields, name=name).with_arch(self.project.arch)
                self._structs[name] = result
            self._pending_types.remove(name)
        return result

    def _parse_Enumeration(self, data):
        name = data["name"]
        if name in self._structs:
            return self._structs[name]
        if name in self._pending_types:
            return RustSimTypeBottom()
        result = None
        variants_data = data["variants"]
        # If variants_data is None, it means the enum is referenced and defined elsewhere
        if variants_data is None:
            actual_data = self._struct_db.get(name, None)
            if actual_data:
                result = self._parse_Enumeration(actual_data)
        else:
            self._pending_types.add(name)
            discriminant_size = data["discriminant_size"]
            variants = []
            for variant_name, variant_data in variants_data.items():
                discriminant = variant_data[0]
                fields_data = variant_data[1]
                fields = []
                for field_data in fields_data:
                    field_ty = self._parse_type(field_data)
                    if field_ty is None:
                        self._pending_types.remove(name)
                        return None
                    fields.append((field_ty, None))
                enum_variant = EnumVariant(variant_name, fields, discriminant, discriminant_size)
                variants.append(enum_variant)
            name_to_variant = {variant.name: variant for variant in variants}
            if name.startswith("core::option::Option") and set(name_to_variant.keys()) == {"Some", "None"}:
                some_variant = name_to_variant["Some"]
                none_variant = name_to_variant["None"]
                result = RustSimTypeOption(
                    none_variant.discriminant,
                    none_variant.discriminant_size,
                    some_variant.fields[0][0],
                    some_variant.discriminant,
                    some_variant.discriminant_size,
                    name=name,
                ).with_arch(self.project.arch)
            elif name.startswith("core::result::Result") and set(name_to_variant.keys()) == {"Ok", "Err"}:
                ok_variant = name_to_variant["Ok"]
                err_variant = name_to_variant["Err"]
                result = RustSimTypeResult(
                    ok_variant.fields[0][0],
                    ok_variant.discriminant,
                    ok_variant.discriminant_size,
                    err_variant.fields[0][0],
                    err_variant.discriminant,
                    err_variant.discriminant_size,
                    name=name,
                ).with_arch(self.project.arch)
            else:
                result = RustSimEnum(name=name, variants=variants).with_arch(self.project.arch)
            self._structs[name] = result
            self._pending_types.remove(name)
        return result

    def _parse_Array(self, data):
        ele_ty = self._parse_type(data["ele_type"])
        length = data["length"]
        if ele_ty is not None:
            return RustSimTypeArray(ele_ty, length).with_arch(self.project.arch)
        return None

    def _parse_type(self, data):
        kind = data.get("kind", None)
        match kind:
            case "Pointer":
                return self._parse_Pointer(data)
            case "Primitive":
                return self._parse_Primitive(data)
            case "Struct":
                return self._parse_Struct(data)
            case "Enumeration":
                return self._parse_Enumeration(data)
            case "Array":
                return self._parse_Array(data)
            case "None":
                return None
        l.warning("Unrecognized type: %s", data)
        return None

    def _parse_Prototype(self, data):
        args = [self._parse_type(arg_data) for arg_data in data["args"]]
        if None in args:
            return None
        ret_ty = self._parse_type(data["returnty"])
        return RustSimTypeFunction(args, ret_ty)

    def _analyze(self):
        rustc_version = RustVersionIdentifier(self.project).identify_rust_version()
        l.info("Rust version: %s", rustc_version)
        type_db_filename = f"{rustc_version}.json"
        type_db_path = Path(__file__).parent.joinpath("type_db").joinpath(type_db_filename)
        if not type_db_path.exists():
            l.warning(f"Type database for Rust version {rustc_version} not found at {type_db_path}.")
            return
        type_db_json = json.loads(type_db_path.read_text())
        self._struct_db = {struct_data["name"]: struct_data for struct_data in type_db_json["structs"]}
        for struct_name, struct_data in self._struct_db.items():
            self._parse_type(struct_data)
        l.info("Loaded %d structs from type database.", len(self._structs))

        prototype_db = type_db_json["functions"]
        cc_cls = default_cc(self.project.arch.name)
        cc = cc_cls(self.project.arch) if cc_cls else None
        name_to_func = defaultdict(list)
        for addr in self.kb.functions:
            func = self.kb.functions[addr]
            name_to_func[demangle(func.name)].append(func)

        prototypes = []
        for func_data in prototype_db:
            prototype = self._parse_Prototype(func_data["prototype"])
            if prototype is not None:
                prototype = prototype.with_arch(self.project.arch)
                prototypes.append(prototype)
                func_name = func_data["name"]
                for func in name_to_func[func_name]:
                    old_prototype = func.prototype.with_arch(self.project.arch)
                    # Only update the prototype if the argument sizes match
                    if old_prototype and sum(arg_ty.size for arg_ty in old_prototype.args) == sum(
                        arg_ty.size for arg_ty in prototype.args
                    ):
                        func.prototype = prototype
                        func.calling_convention = cc
                        func.is_prototype_guessed = False
                self.project.kb.librust.set_prototype(func_name, prototype)
        l.info("Loaded %d functions from type database.", len(prototypes))


AnalysesHub.register_default("TypeDBLoader", TypeDBLoader)
