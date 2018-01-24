import string
from collections import defaultdict
import cle

from .labels import Label, DataLabel, FunctionLabel, ObjectLabel, NotypeLabel

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

    def new_label(self, addr, name=None, is_function=None, force=False):

        if force:
            if self.binary.main_nonexecutable_regions_contain(addr):
                label = DataLabel(self.binary, addr, name=name)
            else:
                label = Label.new_label(self.binary, name=name, original_addr=addr)
            self.addr_to_label[addr].append(label)
            return label

        if addr in self.addr_to_label:
            return self.addr_to_label[addr][0]


        # If armel and we have a pointer to a string pointer, make some bold assumptions
        # TODO: handle this better
        if self.project.arch.name == "ARMEL":
            # Label the nearby pointer to our data, but also label that data
            label = DataLabel(self.binary, addr)

            # Do an extra dereference
            string_addr = self.binary.fast_memory_load(addr, 4, int)
            this_string = self.binary.fast_memory_load(string_addr, 15, "char")

            if this_string and this_string[0] in string.printable:

            # Label the existing pointer as junk so we can use the label in the LDR and then string itself
            # and not have it defined twice
                junk_label = DataLabel(self.binary, addr, name=label.name+"_junk")
                self.addr_to_label[addr].append(junk_label)

                if this_string and "\x00" in this_string:
                    this_string = this_string[:this_string.index("\x00")]

                label = Label.new_label(self.binary, name=label.name, original_addr=string_addr)
                self.addr_to_label[string_addr].append(label)

                #l.debug("Identified pc-relative reference to 0x{:x} which points to 0x{:x} => {}. Labeled as '{}'".format(
                #    addr, string_addr, this_string, label))
                return label


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

            # These $d labels are never referenced by code we execute(?), but they are referenced
            # in a few places so we need them to be defined correctly
            if self.project.arch.name == "ARMEL" and symbol_name == "$d":
                string_addr = self.binary.fast_memory_load(addr, 4, int)
                this_string = self.binary.fast_memory_load(string_addr, 15, "char")

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
                # notype
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


