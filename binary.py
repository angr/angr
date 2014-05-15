#!/usr/bin/env python

# pylint: disable=W0703

# for the pybfd import error:
# pylint: disable=F0401

import os
import struct
import logging
import pybfd.bfd
import subprocess

import idalink
import simuvex

from .helpers import once
# radare2
import r2.r_core
import re

l = logging.getLogger("angr.binary")

toolsdir = os.path.dirname(os.path.realpath(__file__)) + "/tools"


class ImportEntry(object):

    def __init__(self, module_name, ea, name, entry_ord):
        self.module_name = module_name
        self.ea = ea
        self.name = name
        self.ord = entry_ord


class ExportEntry(object):

    def __init__(self, index, ordinal, ea, name):
        self.index = index
        self.oridinal = ordinal
        self.ea = ea
        self.name = name


class StringItem(object):

    def __init__(self, ea, value, length):
        self.ea = ea
        self.value = value
        self.length = length


class Binary(object):

    """
    This class provides basic information on binary objects, such as
    imports, exports, etc.
    """

    def __init__(self, filename, arch, project, base_addr=None, allow_pybfd=True, allow_r2=True):

        # A ref to project
        if project is None:
            l.warning("project is None")
        self._project = project

        # location info
        self.dirname = os.path.dirname(filename)
        self.filename = os.path.basename(filename)
        self.fullpath = filename

        # arch
        self.arch = arch

        # other stuff
        self.self_functions = []
        self.added_functions = []
        self.import_list = []
        self.current_module_name = None
        self._custom_entry_point = None

        self.bfd = None
        if allow_pybfd:
            # pybfd
            try:
                self.bfd = pybfd.bfd.Bfd(filename)
            except (pybfd.bfd_base.BfdException, TypeError) as ex:
                self.bfd = None
                l.warning("pybfd raised an exception: %s", ex)

        if allow_r2:
            # radare2
            self.rcore = r2.r_core.RCore()
            self.rcore.file_open(self.fullpath, 0, 0)
            self.rcore.bin_load(None)
            r2_bin_info = self.rcore.bin.get_info()
            if r2_bin_info is None:
                l.warning("An error occurred in radare2 when loading the binary.")

        # set the base address
        # self.base = base_addr if base_addr is not None else 0
        # self.rcore.bin.get_baddr()
        if base_addr is not None:
            self.base = base_addr
        else:
            self.rcore.bin.get_baddr()

        # IDA
        processor_type = self.arch.ida_processor
        ida_prog = "idal" if self.arch.bits == 32 else "idal64"
        pull = base_addr is None
        self.ida = idalink.IDALink(filename, ida_prog=ida_prog, pull=pull, processor_type=processor_type)
        if base_addr is not None:
            if self.min_addr() >= base_addr:
                l.debug("It looks like the current idb is already rebased!")
            else:
                if self.ida.idaapi.rebase_program(
                        base_addr, self.ida.idaapi.MSF_FIXONCE |
                        self.ida.idaapi.MSF_LDKEEP) != 0:
                    raise Exception("Rebasing of %s failed!", self.filename)

            self.ida.remake_mem()

        # cache the qemu symbols
        export_names = [e[0] for e in self.get_exports()]
        self.ida_symbols = self.ida_lookup_symbols(export_names)
        self.qemu_symbols = self.qemu_lookup_symbols(list(set(export_names) - set(self.ida_symbols.keys())))

        l.debug("Resolved %d exports into %d ida symbols and %d qemu symbols.",
                len(export_names), len(self.ida_symbols),
                len(self.qemu_symbols))

    def get_lib_names(self):

        patterns = [ ".dll$", ".so$", "\.so\.[\d]+$" ]

        if self.bfd is None:
            l.warning("Unable to get dependencies without BFD support.")
            return []
        try:
            syms = self.bfd.sections['.dynstr'].content.split('\x00')
            for s in syms:
                for pat in patterns:
                    if re.findall(pat,s):
                        ret.append(s)
            l.debug("dynstr: %s", ret)
        except Exception:
            ret = []
            l.debug("warning: found no lib names, will import all .so files \
                    from the current directory")
            dir = os.path.dirname(self.fullpath)
            for lib in os.listdir(dir):
                for pat in patterns:
                    if re.findall(pat,lib):
                        ret.append(lib)
            l.debug(".so files in current directory: %s", ret)
        return ret

    @once
    def get_imports(self):
        """ Get program imports from nm"""
        p_nm = subprocess.Popen(
            ["nm", "-D", self.fullpath], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        result_nm = p_nm.stdout.readlines()
        imports = []
        if(len(result_nm) == 0):
            im_file = self.fullpath + ".imports"
            l.debug("nm found no imports :(. Manual loading symbols from %s...", im_file)
            if os.path.exists(im_file):
                f = open(im_file,'r')
                list = f.readlines()
                for name in list:
                    symb = re.split('\s*', name)[1] # Parses IDA's clipboard output: (address symbol_name)
                    imports.append([symb, "T"]) # Tmp hack - TODO: get proper type
                l.debug("Read %d imports from imports.txt", len(imports))

        else:
            for nm_out in result_nm:
                lib_symbol = nm_out.split()
                ntype = lib_symbol[0 if len(lib_symbol) == 2 else 1]
                if ntype not in "Uuvw":
                    # skip anything but imports
                    continue

                sym = lib_symbol[-1]
                imports.append([sym, ntype])

        return imports


    @once
    def get_exports(self):
        """ Get program exports from nm"""
        p_nm = subprocess.Popen( ["nm", "-D", self.fullpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result_nm = p_nm.stdout.readlines()
        exports = []
        if(len(result_nm) == 0):
            l.debug("nm found no exports :(. Trying with IDA.")
            # Fall back on IDA
            for name in self.ida_get_exports():
                #l.debug("name: %s",name[3])
                exports.append([name[3],"T"]) # hack: append bullshit type to everything
            l.debug("IDA found %d exports", len(exports))
        else:
            for nm_out in result_nm:
                lib_symbol = nm_out.split()
                ntype = lib_symbol[0 if len(lib_symbol) == 2 else 1]
                if ntype not in "ABCDGRSTVWi":
                    # skip anything but exports
                    continue

                sym = lib_symbol[-1]
                exports.append([sym, ntype])

        return exports

    def ida_get_exports(self):
        return self.ida.idautils.Entries()

    def qemu_lookup_symbols(self, symbols):
        """ Look for symbols addresses using Qemu"""
        if len(symbols) == 0:
            return {}

        l.debug("Looking up %d symbols on %s", len(symbols), self.filename)

        qemu = 'qemu-' + self.arch.qemu_name
        arch_dir = toolsdir + '/' + self.arch.qemu_name
        opt = 'LD_LIBRARY_PATH=' + self.dirname
        cmdline = [qemu, '-L', arch_dir, '-E', opt, arch_dir + '/sym', self.fullpath] + symbols

        p_qe = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result_qe = p_qe.stdout.readlines()
        errors_qe = [ e for e in p_qe.stderr.readlines() if 'ERROR: ioctl(' not in e ]

        if len(errors_qe) > 0:
            l.error("QEMU received errors: \n\t%s", "\n\t".join(errors_qe))

        l.debug("... sym return %d lines", len(result_qe))
        if len(result_qe) < 1:
            return {}

        addrs = {}
        for r in result_qe:
            name, addr = r.strip().split(' ')
            addr = int(addr, 16) + self.base
            addrs[name] = addr

        return addrs

    def ida_lookup_symbols(self, symbols):
        """ Look for symbols addresses using IDA"""
        addrs = {}

        for sym in symbols:
            addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
            if addr != self.ida.idc.BADADDR:
                addrs[sym] = addr

        return addrs

    def get_symbol_addr(self, sym, ida=True, qemu=True):
        """
        Get the address from a symbol using IDA or Qemu
        @param sym: the symbol
        @param ida: use IDA
        @param qemu: use quemu
        """

        addr = None

        if ida:
            if sym in self.ida_symbols:
                addr = self.ida_symbols[sym]
            else:
                addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
                if addr == self.ida.idc.BADADDR:
                    addr = None

        # if IDA doesn't know the symbol, use QEMU
        if qemu is True and addr is None and sym in self.qemu_symbols:
            l.debug("Looking up %s in QEMU...", sym)
            addr = self.qemu_symbols[sym]
            l.debug("... got 0x%x", addr)

        return addr

    def resolve_import(self, sym, new_val):
        """ Resolve imports (PLT)"""
        fmt = self.arch.struct_fmt

        l.debug("Resolving import symbol %s to 0x%x", sym, new_val)

        plt_addr = None

        # extern_start = [ _ for _ in self.ida.idautils.Segments() if
        # self.ida.idc.SegName(_) == "extern" ][0]
        #extern_end = self.ida.idc.SegEnd(extern_start)
        # extern_dict = { self.ida.idc.Name(_): _ for _ in
        # self.ida.idautils.Heads(extern_start, extern_end) }

        # first, try IDA's _ptr crap
        if plt_addr is None:
            l.debug("... trying %s_ptr.", sym)
            plt_addr = self.get_symbol_addr(sym + "_ptr", qemu=False)
            if plt_addr is not None:
                update_addrs = [plt_addr]

        # now try the __imp_name
        if plt_addr is None:
            l.debug("... trying __imp_%s.", sym)
            plt_addr = self.get_symbol_addr("__imp_" + sym, qemu=False)
            if plt_addr is not None:
                update_addrs = list(self.ida.idautils.DataRefsTo(plt_addr))

        # finally, try the normal name
        if plt_addr is None:
            l.debug("... trying %s.", sym)
            plt_addr = self.get_symbol_addr(sym, qemu=False)
            if plt_addr is not None:
                update_addrs = list(self.ida.idautils.DataRefsTo(plt_addr))

                if len(update_addrs) == 0:
                    l.debug(
                        "... got no DataRefs. This can happen on PPC."
                        + "Trying CodeRefs")
                    update_addrs = list(
                        self.ida.idautils.CodeRefsTo(plt_addr, 1))

        if plt_addr is None:
            l.warning("Unable to resolve import %s", sym)
            return

        l.debug("... %d plt refs found.", len(update_addrs))

        if self.arch.name == "MIPS32":
            # FIXME: MIPS32 ELFS seems to be hard to directly modify the
            # original instruction in place. Instead, we are using a
            # 'trampoline' to help us redirect the control flow.
            self._project.add_custom_sim_procedure(plt_addr, \
                                    simuvex.SimProcedures['stub']['Redirect'], \
                                    {'redirect_to': new_val})
        else:
            packed = struct.pack(fmt, new_val)
            for addr in update_addrs:
                l.debug("... setting 0x%x to 0x%x", addr, new_val)
                for n, p in enumerate(packed):
                    self.ida.mem[addr + n] = p

    def min_addr(self):
        """ Get the min address of the binary (IDA)"""
        nm = self.ida.idc.NextAddr(0)
        pm = self.ida.idc.PrevAddr(nm)

        if pm == self.ida.idc.BADADDR:
            return nm
        else:
            return pm

    def max_addr(self):
        """ Get the max address of the binary (IDA)"""
        pm = self.ida.idc.PrevAddr(self.ida.idc.MAXADDR)
        nm = self.ida.idc.NextAddr(pm)

        if nm == self.ida.idc.BADADDR:
            return pm
        else:
            return nm

    def get_mem(self):
        """ Get memory (IDA)"""
        return self.ida.mem

    def get_perms(self):
        """ Get memory permissions (IDA)"""
        return self.ida.perms

    # Gets the entry point of the binary.
    def entry(self):
        """ Get the entry point of the binary (from IDA)"""
        if self._custom_entry_point is not None:
            return self._custom_entry_point
        return self.ida.idc.BeginEA()

    def set_entry(self, entry_point):
        """ Set a custom entry point"""
        self._custom_entry_point = entry_point

    @once
    def exports(self):
        """ Get binary's exports from IDA"""
        export_item_list = []
        for item in list(self.ida.idautils.Entries()):
            i = ExportEntry(item[0], item[1], item[2], item[3])
            export_item_list.append(i)
        return export_item_list

    @once
    def imports(self):
        """ Extract imports from binary (IDA)"""
        import_modules_count = self.ida.idaapi.get_import_module_qty()

        for i in xrange(0, import_modules_count):
            self.current_module_name = self.ida.idaapi.get_import_module_name(
                i)
            self.ida.idaapi.enum_import_names(i, self.import_entry_callback)

        return self.import_list

    @once
    def strings(self):
        """ Extract strings from binary (IDA) """
        ss = self.ida.idautils.Strings()
        string_list = []
        for s in ss:
            stringItem = StringItem(s.ea, str(s), s.length)
            string_list.append(stringItem)

        return string_list

    def dataRefsTo(self, ea):
        """
        Get data references to address ea
        @param ea: the address where the references point to
        """
        refs = self.ida.idautils.DataRefsTo(ea)
        refs_list = []
        for ref in refs:
            refs_list.append(ref)

        return refs_list

    def codeRefsTo(self, ea):
        """
        Get code references to ea (from IDA)
        @param ea: the address where the references point to
        """

        refs = self.ida.idautils.CodeRefsTo(ea, True)
        refs_list = []
        for ref in refs:
            refs_list.append(ref)

        return refs_list

    # Callbacks
    def import_entry_callback(self, ea, name, entry_ord):
        item = ImportEntry(self.current_module_name, ea, name, entry_ord)
        self.import_list.append(item)
        return True
