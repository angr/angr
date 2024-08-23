from __future__ import annotations
import os
import re
import logging
from sortedcontainers import SortedList

from ... import Analysis, register_analysis
from .base import BaseStructuredCodeGenerator, InstructionMapping, PositionMapping
from ....knowledge_plugins.functions.function import Function


l = logging.getLogger(__name__)


class ImportedLine:
    def __init__(self, addr):
        self.tags = {"ins_addr": addr}


class ImportSourceCode(BaseStructuredCodeGenerator, Analysis):
    def __init__(self, function, flavor="source", source_root=None, encoding="utf-8"):
        super().__init__(flavor=flavor)

        if isinstance(function, (int, str)):
            function = self.kb.functions[function]
        self.function: Function = function
        self._source_root = source_root
        self._encoding = encoding

        self.regenerate_text()

        if flavor is not None and self.text:
            self.kb.structured_code[(function.addr, flavor)] = self

    def regenerate_text(self):
        cache = {}
        ranges = self._compute_function_ranges(cache=cache)
        line_to_addr = self._compute_line_to_addr(ranges)

        self.stmt_posmap = PositionMapping()
        self.insmap = InstructionMapping()
        pos = 0
        all_lines = []
        for filename, range_start, range_end in ranges:
            these_lines = self._open_file(filename)[range_start - 1 : range_end - 1 + 1]
            all_lines.extend(these_lines)
            for idx, line_text in enumerate(these_lines):
                addr = line_to_addr[(filename, range_start + idx)]
                if addr is not None:
                    self.stmt_posmap.add_mapping(pos, len(line_text), ImportedLine(addr))
                    self.insmap.add_mapping(addr, pos + len(line_text) - len(line_text.lstrip(" \t")))
                pos += len(line_text)

        self.text = "".join(all_lines)

    def _locate_file(self, filename):
        if os.path.isfile(filename):
            return filename
        if self._source_root is None:
            return None

        filename = filename.strip("/\\")
        path_keys = re.split("[/\\\\]", filename)
        for i in range(len(path_keys)):
            maybe_path = os.path.join(self._source_root, *path_keys[i:])
            if os.path.isfile(maybe_path):
                return maybe_path

        return None

    def _open_file(self, name, cache=None):
        if cache is None:
            cache = {}
        if name in cache:
            return cache[name]
        local_name = self._locate_file(name)
        if local_name is None:
            l.warning("Could not find a local copy of %s", name)
            cache[name] = None
            return None
        with open(local_name, encoding=self._encoding) as fp:
            line_data = fp.readlines()
        cache[name] = line_data
        return line_data

    def _compute_function_ranges(self, cache=None):
        if cache is None:
            cache = {}

        obj = self.project.loader.find_object_containing(self.function.addr)
        if obj is None:
            l.warning("No object contains function %s", self.function.name)
            return []

        if self.function.addr not in obj.addr_to_line:
            l.info("No line data for function %s", self.function.name)
            return []

        lines = SortedList()
        for block in self.function.blocks:
            for insn in block.instruction_addrs:
                if insn in obj.addr_to_line:
                    lines.update((*filename_line, insn) for filename_line in obj.addr_to_line[insn])

        ranges = []
        for filename, line, _ in lines:
            if any(r[0] == filename and r[1] <= line <= r[2] for r in ranges):
                continue
            file_lines = self._open_file(filename, cache=cache)
            if file_lines is None:
                continue
            if line - 1 >= len(file_lines) or line - 1 < 0:
                # a non-existent line number is specified. skip this record
                l.warning(
                    "Line number %d does not exist in file %s. It might be the wrong source code file.", line, filename
                )
                continue
            range_start = line
            range_end = line

            # find the first { on the line
            # find the matching }
            # scan backwards for any lines that aren't blank and don't have {}; on them
            # scan forwards for any lines continued via \
            col = file_lines[range_start - 1].find("{")
            if col != -1:
                col += 1
                stack = 1
                while range_end - 1 < len(file_lines):
                    while col < len(file_lines[range_end - 1]):
                        ch = file_lines[range_end - 1][col]
                        if ch == "{":
                            stack += 1
                        elif ch == "}":
                            stack -= 1
                        if stack == 0:
                            break
                        col += 1
                    else:
                        col = 0
                        range_end += 1
                        continue
                    break

            maybe_prev_line = range_start - 1
            while maybe_prev_line >= 0:
                linedata = file_lines[maybe_prev_line - 1].strip()
                if linedata and not any(c in linedata for c in "{};"):
                    range_start = maybe_prev_line
                    maybe_prev_line -= 1
                else:
                    break

            while range_end - 1 < len(file_lines) - 1:
                linedata = file_lines[range_end - 1].strip()
                if linedata.endswith("\\"):
                    range_end += 1
                else:
                    break

            if any(
                r[0] == filename and (r[1] <= range_start <= r[2] or range_start <= r[1] <= range_end) for r in ranges
            ):
                l.error("Detected line ranges are overlapping?")
            ranges.append((filename, range_start, range_end))

        return ranges

    def _compute_line_to_addr(self, ranges):
        result = {}
        for filename, range_start, range_end in ranges:
            for line in range(range_start, range_end + 1):
                result[(filename, line)] = None

        obj = self.project.loader.find_object_containing(self.function.addr)
        if obj is None:
            l.error("There is a function whose address does not correspond to any loaded object")
            return {}

        for addr, filename_line in obj.addr_to_line.items():
            if filename_line in result:
                result[filename_line] = addr

        return result


register_analysis(ImportSourceCode, "ImportSourceCode")
