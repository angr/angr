#!/usr/bin/env python
"""
Creates an archinfo-compatible architecture definition from SLEIGH specs.
"""
# FIXME:
#  - Definition consistency check test cases
#  - Transfering memory space representation information (angr assumes shared code)
#  - Transferring additional details (compiler specs, calling convention, etc)

from archinfo.arch import Register

import os
import os.path
import logging
import pypcode


l = logging.getLogger(__name__)

def find_matching_cid(lang, desired):
    for cid in lang.cspecs:
        if cid[0] == desired:
            return cid
    return None

def create_archinfo_class_from_lang(lang:pypcode.ArchLanguage) -> str:
    """
    Construct an archinfo class definition from pypcode architecture definitions.
    """
    ctx = pypcode.Context(lang)
    archinfo_regs = {
        rname.lower(): Register(rname.lower(), r.size, r.offset)
            for rname, r in ctx.registers.items()
            }

    # Get program counter register
    pc_offset = None
    pc_tag = lang.pspec.find('programcounter')
    if pc_tag is not None:
        pc_reg = pc_tag.attrib.get('register', None)
        if pc_reg is not None:
            # FIXME: Assumes RAM space
            pc_offset = ctx.registers[pc_reg].offset
            aliases = {'pc', 'ip'}
            aliases.discard(pc_reg.lower())
            archinfo_regs[pc_reg.lower()].alias_names = tuple(aliases)

    if pc_offset is None:
        l.warning('Unknown program counter register offset?')
        pc_offset = 0x80000000

    # Get stack pointer register
    sp_offset = None

    if len(lang.cspecs):
        cspec_id = find_matching_cid(lang, 'default') \
                   or find_matching_cid(lang, 'gcc') \
                   or list(lang.cspecs)[0]
        cspec = lang.cspecs[cspec_id]
        sp_tag = cspec.find('stackpointer')
        if sp_tag is not None:
            sp_reg = sp_tag.attrib.get('register', None)
            if sp_reg is not None:
                # FIXME: Assumes RAM space
                sp_offset = ctx.registers[sp_reg].offset

    if sp_offset is None:
        l.warning('Unknown stack pointer register offset?')
        sp_offset = 0x80000008

    bits = int(lang.size)
    archname = lang.id
    endness = {'little': 'Endness.LE', 'big': 'Endness.BE'}[lang.endian]
    def stringify_reg(r):
        return f"Register('{r.name}', {r.size}, {hex(r.vex_offset)}" \
            + ((', alias_names=' + str(r.alias_names)) if len(r.alias_names) else '') \
            + ")"
    reg_list_str = ",\n        ".join([stringify_reg(r) for r in archinfo_regs.values()])
    archname_san = ''.join([c if c.isalnum() else '_' for c in archname])
    classname = 'ArchPcode_' + archname_san
    return (classname, f"""class {classname}(ArchPcode):
    name = '{archname}'
    pcode_arch = '{archname}'
    description = {repr(lang.description)}
    bits = {bits}
    ip_offset = {hex(pc_offset)}
    sp_offset = {hex(sp_offset)}
    bp_offset = sp_offset
    instruction_endness = {endness}
    register_list = [
        {reg_list_str}
    ]

register_arch(['{archname.lower()}'], {bits}, {endness}, {classname})
""")

def main():
    archdir = os.path.dirname(os.path.abspath(__file__))
    langs = [lang for arch in pypcode.Arch.enumerate()
                     for lang in arch.languages]
    imports = []
    for i, lang in enumerate(langs):
        classname, classdef = create_archinfo_class_from_lang(lang)
        imports.append(classname)
        with open(os.path.join(archdir, f'{classname}.py'), 'w') as f:
            print('Generating arch definition for %s (%d of %d)' % (lang.id, i+1, len(langs)))
            f.write(
                "###\n"
                "### This file was automatically generated\n"
                "###\n"
                "\n"
                "from archinfo.arch import register_arch, Endness, Register\n"
                "\n"
                "from .common import ArchPcode\n"
                "\n"
                "\n"
                )
            f.write(classdef)
    with open(os.path.join(archdir, '__init__.py'), 'w') as f:
        for classname in imports:
            f.write(f'from .{classname} import {classname}\n')
        f.write('from .common import *\n')

if __name__ == '__main__':
    main()
