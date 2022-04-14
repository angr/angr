from typing import Union, Type

import pypcode
from archinfo.arch import register_arch, Endness, Register, Arch
from archinfo.tls import TLSArchInfo


class ArchPcode(Arch):
    """
    archinfo interface to pypcode architectures. Provides mapping for minimal
    architectural info like register file map, endianness, bit width, etc.
    """

    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)
    pcode_arch = None

    def __init__(self, *vargs, **kwargs):
        lang = self._lang_id_to_lang(self.pcode_arch)
        ctx = pypcode.Context(lang)

        # Build registers list
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
                for alias in aliases:
                    archinfo_regs.pop(alias, None)
                archinfo_regs[pc_reg.lower()].alias_names = tuple(aliases)

        if pc_offset is None:
            l.warning('Unknown program counter register offset?')
            pc_offset = 0x80000000

        # Get stack pointer register
        sp_offset = None
        if len(lang.cspecs):
            def find_matching_cid(lang, desired):
                for cid in lang.cspecs:
                    if cid[0] == desired:
                        return cid
                return None
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

                if sp_reg.lower() != 'sp' and 'sp' in archinfo_regs:
                    del archinfo_regs['sp']
                    archinfo_regs[sp_reg.lower()].alias_names += ('sp',)

        if sp_offset is None:
            l.warning('Unknown stack pointer register offset?')
            sp_offset = 0x80000008

        self.instruction_alignment = 1
        self.ip_offset = pc_offset
        self.sp_offset = sp_offset
        self.bp_offset = sp_offset
        self.register_list = archinfo_regs.values()
        self.initial_sp = (0x8000 << (self.bits-16)) - 1
        super().__init__(endness=self.endness, instruction_endness=self.instruction_endness)

    @classmethod
    def arch_from_lang_id(cls, lang_id: str) -> 'ArchPcode':
        return cls.arch_class_from_lang_id(lang_id)()

    @classmethod
    def arch_class_from_lang_id(cls, lang_id: str) -> Type['ArchPcode']:
        return cls.arch_class_from_lang(cls._lang_id_to_lang(lang_id))

    @staticmethod
    def _lang_id_to_lang(lang_id: str) -> pypcode.ArchLanguage:
        for arch in pypcode.Arch.enumerate():
            for lang in arch.languages:
                if lang.id == lang_id:
                    return lang
        raise Exception(f'Language with id {lang_id} not found')

    @classmethod
    def arch_class_from_lang(cls, lang: pypcode.ArchLanguage) -> Type['ArchPcode']:
        endness = {'little': Endness.LE, 'big': Endness.BE}[lang.endian]
        return type('ArchPcode_' + ''.join([('_', c)[c.isalnum()] for c in lang.id]), (cls,),dict(
            __doc__='Auto-generated archinfo class for pypcode language {lang_id} ({lang.description})',
            name=lang.id, description=lang.description, pcode_arch=lang.id,
            bits=int(lang.size), endness=endness, instruction_endness=endness))
