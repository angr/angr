import importlib
import logging
import os.path
import re
from collections import defaultdict
from pathlib import Path

from angr.rust.definitions.commit_versions import COMMIT_VERSIONS
from angr.analyses import Analysis, AnalysesHub
from angr.knowledge_plugins.cfg import MemoryDataSort


l = logging.getLogger(__name__)


class KnownTypeLoader(Analysis):
    def __init__(self):
        self.cfg = self.project.kb.cfgs.get_most_accurate()

        self._analyze()

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

    def _analyze(self):
        rustc_version = self._extract_rustc_version() or "1.61.0"
        if rustc_version:
            l.debug(f"Found rustc version: {rustc_version}")
            known_structs_path = (
                Path(__file__)
                .parent.parent.joinpath("definitions")
                .joinpath("known_types")
                .joinpath("structs_" + rustc_version + ".py")
            )
            known_prototypes_path = (
                Path(__file__)
                .parent.parent.joinpath("definitions")
                .joinpath("known_types")
                .joinpath("prototypes_" + rustc_version + ".py")
            )
            if known_structs_path.exists():
                spec = importlib.util.spec_from_file_location("known_structs", known_structs_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for struct_name, struct_ty in module.default_structs.items():
                    self.project.kb.known_structs[struct_name] = struct_ty.with_arch(self.project.arch)
            if known_prototypes_path.exists():
                spec = importlib.util.spec_from_file_location("known_prototypes", known_prototypes_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                name_to_func = defaultdict(list)
                for addr in self.kb.functions:
                    func = self.kb.functions[addr]
                    name_to_func[func.demangled_name].append(func)

                for func_name, prototype in module.generate_known_rust_prototypes(self.project).items():
                    prototype = prototype.with_arch(self.project.arch)
                    for func in name_to_func[func_name]:
                        func.prototype = prototype
                    self.project.kb.librust.set_prototype(func_name, prototype)


AnalysesHub.register_default("KnownTypeLoader", KnownTypeLoader)
