from typing import List
import copy

import pycparser

from angr.sim_type import make_preamble, _decl_to_type, SimStruct, SimUnion


class PatchAnalysis:
    def __init__(self):
        pass

    def analyze_patch(self, content):
        original_lines: List[str] = [ ]
        new_lines: List[str] = [ ]
        # analyze each line and separate them into two categories

        for line in content.split("\n"):
            if not line:
                continue
            first_char = line[0]
            line = line[1:]

            # remove comments
            if "//" in line:
                line = line[:line.index("//")]

            if first_char == " ":
                original_lines.append(line)
                new_lines.append(line)
            elif first_char == "-":
                original_lines.append(line)
            elif first_char == "+":
                new_lines.append(line)
            else:
                continue

        if not original_lines and not new_lines:
            raise ValueError("No lines start with supporting leading characters. The patch might be invalid.")

        # here is the tricky bit: attempt parsing
        # shit may fail, but we try our best!

        all_defs = {}
        all_extra_types = {}

        # first pass: parsing line by line
        for line in original_lines:

            # hack: if the line ends with an open curly brace, replace it with a semicolon
            if line.strip(" ").endswith("{"):
                line = line.strip(" ")[:-1] + ";"

            try:
                defs, extra_types = self.attempt_parsing(line)
            except Exception:
                continue
            # print(line)
            # print(ast)
            # print(" ")

            # what is this ast that we just got back?
            if not defs:
                continue
            all_defs.update(defs)
            all_extra_types.update(extra_types)

        return all_defs, all_extra_types

    def attempt_parsing(self, content: str):
        preamble, ignoreme = make_preamble()
        ast = pycparser.CParser().parse(preamble + content)
        defs = { }
        extra_types = { }

        for piece in ast.ext:
            if isinstance(piece, pycparser.c_ast.FuncDef):
                defs[piece.decl.name] = _decl_to_type(piece.decl.type, extra_types)
            elif isinstance(piece, pycparser.c_ast.Decl):
                ty = _decl_to_type(piece.type, extra_types)
                if piece.name is not None:
                    defs[piece.name] = ty

                # Don't forget to update typedef types
                if (isinstance(ty, SimStruct) or isinstance(ty, SimUnion)) and ty.name != '<anon>':
                    for _, i in extra_types.items():
                        if i.name == ty.name:
                            if isinstance(ty, SimStruct):
                                i.fields = ty.fields
                            else:
                                i.members = ty.members

            elif isinstance(piece, pycparser.c_ast.Typedef):
                extra_types[piece.name] = copy.copy(_decl_to_type(piece.type, extra_types))
                extra_types[piece.name].label = piece.name

        for ty in ignoreme:
            del extra_types[ty]

        return defs, extra_types
