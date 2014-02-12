#!/usr/bin/env python

# pylint: disable=W0703

# for the pybfd import error:
# pylint: disable=F0401

import os
import struct
import idalink
import logging
import pybfd.bfd
import subprocess
from .function import Function
from .helpers import once

# radare2
import r2.r_core

l = logging.getLogger("angr.binary")

arch_bits = {}
arch_bits["X86"] = 32
arch_bits["AMD64"] = 64
arch_bits["ARM"] = 32
arch_bits["PPC32"] = 32
arch_bits["PPC64"] = 64
arch_bits["S390X"] = 32
arch_bits["MIPS32"] = 32

qemu_arch = {}
qemu_arch['X86'] = 'i386'
qemu_arch['AMD64'] = 'x86_64'
qemu_arch['ARM'] = 'arm'
qemu_arch['PPC32'] = 'ppc'
qemu_arch['PPC64'] = 'ppc64'
qemu_arch['S390x'] = 's390x'
qemu_arch['MIPS32'] = 'mips'

arch_ida_processor = {}
arch_ida_processor['X86'] = 'metapc'
arch_ida_processor['AMD64'] = 'metapc'
arch_ida_processor['ARM'] = 'armb'  # ARM Big Endian
arch_ida_processor['PPC32'] = 'ppc'  # PowerPC Big Endian
arch_ida_processor['MIPS32'] = 'mipsl'  # MIPS little endian

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

    def __init__(self, filename, arch="AMD64", base_addr=None):

        # location info
        self.dirname = os.path.dirname(filename)
        self.filename = os.path.basename(filename)
        self.fullpath = filename

        # other stuff
        self.self_functions = []
        self.added_functions = []
        self.import_list = []
        self.current_module_name = None
        self._custom_entry_point = None

        # arch info
        self.arch = arch
        self.bits = arch_bits[arch]

        # pybfd
        try:
            self.bfd = pybfd.bfd.Bfd(filename)
            self.bits = self.bfd.arch_size
        except pybfd.bfd_base.BfdException as ex:
            l.warning("pybfd raised an exception: %s" % ex)

        # radare2
        self.rcore = r2.r_core.RCore()
        self.rcore.file_open(self.fullpath, 0, 0)
        self.rcore.bin_load(None)
        r2_bin_info = self.rcore.bin.get_info()
        if r2_bin_info is None:
            l.warning("An error occurred in radare2 when loading the binary.")
        else:
            self.bits = r2_bin_info.bits

        # set the base address
        # self.base = base_addr if base_addr is not None else 0
        # self.rcore.bin.get_baddr()
        if base_addr is not None:
            self.base = base_addr
        else:
            self.rcore.bin.get_baddr()

        # IDA
        if arch not in arch_ida_processor:
            raise Exception("Unsupported architecture")
            # TODO: Support other processor types
        processor_type = arch_ida_processor[arch]
        ida_prog = "idal" if self.bits == 32 else "idal64"
        pull = base_addr is None
        self.ida = idalink.IDALink(filename, ida_prog=ida_prog,
                                   pull=pull, processor_type=processor_type)
        if base_addr is not None:
            if self.min_addr() >= base_addr:
                l.debug("It looks like the current idb is already rebased!")
            else:
                if self.ida.idaapi.rebase_program(
                        base_addr, self.ida.idaapi.MSF_FIXONCE |
                        self.ida.idaapi.MSF_LDKEEP) != 0:
                    raise Exception("Rebasing of %s failed!" % self.filename)
                self.ida.remake_mem()

        # cache the qemu symbols
        export_names = [e[0] for e in self.get_exports()]
        print "Exports:", export_names
        self.ida_symbols = self.ida_lookup_symbols(export_names)
        self.qemu_symbols = self.qemu_lookup_symbols(
            list(set(export_names) - set(self.ida_symbols.keys())))

        l.debug("Resolved %d exports into %d ida symbols and %d qemu symbols.",
                len(export_names), len(self.ida_symbols),
                len(self.qemu_symbols))

    def get_lib_names(self):
        if self.bfd is None:
            l.warning("Unable to get dependencies without BFD support.")
            return []
        try:
            syms = self.bfd.sections['.dynstr'].content.split('\x00')
            ret = [s for s in syms if s != self.fullpath and (
                '.so' in s or '.dll' in s)]
        except Exception:
            ret = []
        return ret

    @once
    def get_imports(self):
        """ Get program imports IDA"""
        p_nm = subprocess.Popen(
            ["nm", "-D", self.fullpath], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        result_nm = p_nm.stdout.readlines()
        imports = []

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
        """ Get program exports"""
        p_nm = subprocess.Popen(
            ["nm", "-D", self.fullpath], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        result_nm = p_nm.stdout.readlines()
        exports = []
        for nm_out in result_nm:
            lib_symbol = nm_out.split()
            ntype = lib_symbol[0 if len(lib_symbol) == 2 else 1]
            if ntype not in "ABCDGRSTVWi":
                # skip anything but exports
                continue

            sym = lib_symbol[-1]
            exports.append([sym, ntype])

        return exports

    def qemu_lookup_symbols(self, symbols):
        """ Look for symbols addresses using Qemu"""
        if len(symbols) == 0:
            return {}

        l.debug("Looking up %d symbols on %s", len(symbols), self.filename)

        qemu = 'qemu-' + qemu_arch[self.arch]
        arch_dir = toolsdir + '/' + qemu_arch[self.arch]
        opt = 'LD_LIBRARY_PATH=' + self.dirname
        cmdline = [qemu, '-L', arch_dir, '-E', opt,
                   arch_dir + '/sym', self.fullpath] + symbols
        p_qe = subprocess.Popen(
            cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result_qe = p_qe.stdout.readlines()
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
            #addr = self.qemu_lookup_symbols([ sym ])
            addr = self.qemu_symbols[sym]
            l.debug("QEMU got 0x%x for %s", addr, sym)
            # make sure QEMU and IDA agree
            ida_func = self.ida.idaapi.get_func(addr)
            ida_name = self.ida.idaapi.get_name(0, addr)

            #l.debug("... sym: %s, ida: %s" % (sym, ida_name))

            # TODO: match symbols to IDA symbols better
            sym_al = ''.join(ch for ch in sym if ch.isalnum())
            ida_al = ''.join(ch for ch in ida_name if ch.isalnum())

            if sym_al in ida_al:
                #l.debug("... names (%s and %s) match!" % (sym, ida_name))
                pass
            elif not ida_func:  # data section
                loc_name = "loc_" + ("%x" % addr).upper()
                if ida_name != loc_name:
                    l.warning(
                        ("%s wasn't recognized by IDA as a function." +
                            " IDA name: %s") % (sym, ida_name))
                else:
                    r = self.ida.idc.MakeFunction(addr, self.ida.idc.BADADDR)
                    if not r:
                        raise Exception(
                            "Failure making IDA function at 0x%x for %s." %
                            (addr, sym))
                    ida_func = self.ida.idaapi.get_func(addr)
            elif ida_func.startEA != addr:
                # add the start, end, and name to the self_functions list
                l.warning(
                    ("%s points to 0x%x, which IDA sees as being partially" +
                        " through function at %x. Creating self function.") %
                    (sym, addr, ida_func.startEA))
                # sometimes happens
                if (addr, ida_func.endEA, sym) not in self.self_functions:
                    self.self_functions.append((addr, ida_func.endEA, sym))
        return addr

    @property
    def struct_format(self):
        fmt = ""

        if self.bfd.big_endian:
            fmt += ">"
        elif self.bfd.little_endian:
            fmt += "<"

        if self.bits == 64:
            fmt += "Q"
        elif self.bits == 32:
            fmt += "I"
        elif self.bits == 16:
            fmt += "H"
        elif self.bits == 8:
            fmt += "B"

        return fmt

    def resolve_import(self, sym, new_val):
        """ Resolve imports (PLT)"""
        fmt = self.struct_format

        l.debug("Resolving import symbol %s to 0x%x", sym, new_val)

        plt_addr = None

        # extern_start = [ _ for _ in self.ida.idautils.Segments() if
        # self.ida.idc.SegName(_) == "extern" ][0]
        #extern_end = self.ida.idc.SegEnd(extern_start)
        # extern_dict = { self.ida.idc.Name(_): _ for _ in
        # self.ida.idautils.Heads(extern_start, extern_end) }

        # first, try IDA's __ptr crap
        if plt_addr is None:
            l.debug("... trying %s__ptr." % sym)
            plt_addr = self.get_symbol_addr(sym + "_ptr", qemu=False)
            if plt_addr is not None:
                update_addrs = [plt_addr]

        # now try the __imp_name
        if plt_addr is None:
            l.debug("... trying __imp_%s." % sym)
            plt_addr = self.get_symbol_addr("__imp_" + sym, qemu=False)
            if plt_addr is not None:
                update_addrs = list(self.ida.idautils.DataRefsTo(plt_addr))

        # finally, try the normal name
        if plt_addr is None:
            l.debug("... trying %s." % sym)
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

        l.debug("... %d plt refs found." % len(update_addrs))

        packed = struct.pack(fmt, new_val)
        for addr in update_addrs:
            l.debug("... setting 0x%x to 0x%x" % (addr, new_val))
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

    def functions(self, mem=None):
        """ Extract functions from the binary (IDA)"""
        mem = mem if mem else self.ida.mem

        functions = {}
        for f in self.ida.idautils.Functions():
            name = self.ida.idaapi.get_name(0, f)
            functions[f] = Function(f, self.ida, mem, self.arch, self, name)

        for s, e, n in self.self_functions:
            l.debug("Binary %s creating self function %s at 0x%x" %
                    (self.filename, n, s))
            functions[s] = Function(
                s, self.ida, mem, self.arch, self, name=n, end=e)

        for s, e, n in self.added_functions:
            l.debug("Binary %s creating added function %s at 0x%x" %
                    (self.filename, n, s))
            functions[s] = Function(
                s, self.ida, mem, self.arch, self, name=n, end=e)

        return functions

    def add_function(self, start, end, sym):
        """
        Define a new function
        @param start: the start address
        @param end: the end address
        @param symb: the symbol of the new function
        """
        if (start, end, sym) not in self.added_functions:
            self.added_functions.append((start, end, sym))

    def add_function_chunk(self, addr):
        ida_func = self.ida.idaapi.get_func(addr)
        if not ida_func:
            return

        end = None
        for bb in self.ida.idaapi.FlowChart(ida_func):
            # contiguous blocks
            if end:
                if bb.startEA == end:
                    end = bb.endEA
                else:
                    break
            if bb.startEA == addr:
                end = bb.endEA

        if not end:
            raise Exception(
                "Error in retrieving function chunk starting from address: %s."
                % addr)
        self.add_function(addr, end, self.ida.idaapi.get_name(0, addr))

    @once
    def our_functions(self):
        functions = {}
        remaining_exits = [self.entry()]

        while remaining_exits:
            current_exit = remaining_exits[0]
            remaining_exits = remaining_exits[1:]

            if current_exit not in functions:
                print "New function: 0x%x" % current_exit
                f = Function(current_exit, self.ida, self.arch)
                functions[current_exit] = f
                new_exits = f.exits()
                print "Exits from 0x%x: %s" % (current_exit, [hex(i) for i in
                                                              new_exits])
                remaining_exits += [i for i in new_exits if i != 100]

        return functions

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
