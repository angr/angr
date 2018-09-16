import string
from collections import defaultdict
import cle
import logging

from .labels import Label, DataLabel, FunctionLabel, ObjectLabel, NotypeLabel
l = logging.getLogger("angr.analyses.reassembler")

class SymbolManager(object):
    """
    SymbolManager manages all symbols in the binary.
    """
    def __init__(self, binary, cfg):
        """
        Constructor.

        :param Reassembler binary: The Binary analysis instance.
        :param angr.analyses.CFG cfg: The CFG analysis instance.
        :return: None
        """

        self.binary = binary
        self.project = binary.project
        self.cfg = cfg

        self.addr_to_label = defaultdict(list)

    def label_to_addr(self, label_search):
        for addr, label in self.addr_to_label.items():
            if any([label_search == x.name for x in label]):
                return addr
        return None

    def new_label(self, addr, name=None, is_function=None, force=False, dereference=True, op=None):
        if force:
            if is_function:
                l.warning("Unsupported option combination FORCE and IS_FUNCTION")
            if self.binary.main_nonexecutable_regions_contain(addr):
                label = DataLabel(self.binary, addr, name=name)
            else:
                label = Label.new_label(self.binary, name=name, original_addr=addr)
            self.addr_to_label[addr].insert(0, label)
            #self.addr_to_label[addr].append(label)
            return label

        if addr in self.addr_to_label:
            if not len(self.addr_to_label[addr]):
                l.warning("no labels exist for 0x{:x}".format(addr))
                del self.addr_to_label[addr]
                return self.new_label(addr, name, is_function, force, dereference, op)
            else:
                return self.addr_to_label[addr][0]

        # Check if the address points to a function by checking the plt of main binary
        reverse_plt = self.project.loader.main_object.reverse_plt
        symbols_by_addr = self.project.loader.main_object.symbols_by_addr

        if addr in reverse_plt:
            # It's a PLT entry!
            label = FunctionLabel(self.binary, reverse_plt[addr], addr, plt=True)
        elif addr in symbols_by_addr:
            # It's an extern symbol
            symbol = symbols_by_addr[addr]
            symbol_name = symbol.name

            # $d symbol denotes a pointer for ARM
            if self.project.arch.name == "ARMEL" and symbol_name == "$d":
                string_addr = self.binary.fast_memory_load(addr, 4, int)
                this_string = self.binary.fast_memory_load(string_addr, 15, "char")

                if addr in self.cfg.functions:
                    del self.cfg.functions[addr]
                label = DataLabel(self.binary, addr)
                self.addr_to_label[addr].append(label)
                return label

            # Different architectures use different prefixes
            if '@' in symbol_name:
                symbol_name = symbol_name[ : symbol_name.index('@') ]
            if '%' in symbol_name:
                symbol_name = symbol_name[ : symbol_name.index('%') ]

            # check the type...
            if symbol.type == cle.Symbol.TYPE_FUNCTION:
                # it's a function!
                label = FunctionLabel(self.binary, symbol_name, addr)
            elif symbol.type == cle.Symbol.TYPE_OBJECT:
                # it's an object
                label = ObjectLabel(self.binary, symbol_name, addr)
            elif symbol.type == cle.Symbol.TYPE_NONE:
                # notype - Not on ARM
                if self.project.arch.name == "ARMEL":
                    label = DataLabel(self.binary, addr)
                else:
                    label = NotypeLabel(self.binary, symbol_name, addr)
            elif symbol.type == cle.Symbol.TYPE_SECTION:
                # section label
                # use a normal label instead
                if not name:
                    # handle empty names
                    name = None
                label = Label.new_label(self.binary, name=name, original_addr=addr)
            else:
                raise Exception('Unsupported symbol type %s. Bug Fish about it!' % symbol.type)

        elif (addr is not None and addr in self.cfg.functions) or is_function:
            # It's a function identified by angr's CFG recovery

            if is_function and name is not None:
                function_name = name
            else:
                function_name = self.cfg.functions[addr].name

                # special function name for entry point

#TODO: When we reassemble, gcc will add in _start from libc, so maybe we should do something different here
# such as extracting pointer to main (2nd to last argument to _libc_start_main), and relabling that function to main
# But if we aren't using libc then we can't do this

                if addr == self.project.entry:
                    function_name = "_start"

            label = FunctionLabel(self.binary, function_name, addr)
        elif self.binary.main_nonexecutable_regions_contain(addr):
            label = DataLabel(self.binary, addr)
        else:
            label = Label.new_label(self.binary, name=name, original_addr=addr)

        if addr is not None:
            self.addr_to_label[addr].append(label)

        return label

    def label_got(self, addr, label):
        """
        Mark a certain label as assigned (to an instruction or a block of data).

        :param int addr: The address of the label.
        :param Label label: The label that is just assigned.
        :return: None
        """

        if label in self.addr_to_label[addr]:
            label.assigned = True


