from .plugin import KPlugin
from bintrees import RBTree


class BasicBlocksPlugin(KPlugin):
    """
    Storage for information about the boundaries of basic blocks. Access as kb.basic_blocks.

    :ivar sizes:        A mapping from address to the size of the basic block at that address.
    :ivar interned_ir:  A mapping from address to an IRSB that represents the code at that address.
                        This represents a "permanent cache" of IR, so you may store code here if
                        you have made your own modifications to the project's IR.
    """
    def __init__(self):
        self.sizes = RBTree()
        self.interned_ir = {}

    def set_custom_ir(self, addr, irsb):
        self.sizes[addr] = None
        self.interned_ir[addr] = irsb

    def mark_block(self, addr, size):
        try:
            p_addr, p_size = self.sizes.floor_item(addr)
        except KeyError:
            self.sizes[addr] = size
        else:
            if addr == p_addr:
                if size == p_size:
                    return
                else:
                    raise ValueError("Marked basic block at %#x has inconsistent sizes (%d vs %d)" % (addr, size, p_size))
            elif p_addr + p_size <= addr:
                self.sizes[addr] = size
            elif p_addr + p_size == addr + size:
                self.sizes[addr] = size
                self.sizes[p_addr] = addr - p_addr
            else:
                raise ValueError("Marked basic block has inconsistent endpoints - (%#x, %d) vs (%#x, %d)", (p_addr, p_size, addr, size))


    def copy(self):
        o = BasicBlocksPlugin()
        o.sizes = self.sizes.copy()
        o.interned_ir = dict(self.interned_ir)


class FunctionBoundsPlugin(KPlugin):
    """
    Storage for the boundaries of a function. Access as kb.function_bounds.

    :ivar sizes:    A mapping from function start to the number of continuous bytes that are part
                    of the function starting at its start address
    :ivar extents:  A mapping from function start to a list of tuples of (start addr, size) of
                    additional regions that are part of the function.
    """
    def __init__(self):
        self.sizes = RBTree()
        self.extents = {}

    def copy(self):
        o = FunctionBoundsPlugin()
        o.sizes = self.sizes.copy()
        o.extents = {x: list(y) for x, y in self.extents.iteritems()}


class IndirectJumpsPlugin(KPlugin):
    """
    Storage for information about indirect jumps in the program. Access with kb.indirect_jumps.

    :ivar targets:              Mapping from instruction address to list of possible targets
    :ivar targets_exhaustive:   Mapping from instruction address to a bool of whether or not the
                                corresponding list in the ``targets`` dict is an exhaustive list
    """
    def __init__(self):
        self.targets = {} # 1233 -> [567, 890, 222]
        self.targets_exhaustive = {} # 1233 -> True

    def copy(self):
        o = IndirectJumpsPlugin()
        o.targets = dict(self.targets)
        o.targets_exhaustive = dict(self.targets_exhaustive)


class LabelsPlugin(KPlugin):
    """
    Storage for program labels. Access with kb.labels.

    A label "name" is a tuple of (namespace, label). The global namespace is the empty string.

    :ivar addr_to_names:    Mapping from code or data address to list of names
    :ivar name_to_addr:     Mapping from name to code or data address
    """
    def __init__(self):
        self.addr_to_names = {}
        self.name_to_addr = {}

    def set_label(self, addr, name, add=False):
        if name in self.name_to_addr:
            if self.name_to_addr[name] == addr:
                return
            else:
                raise ValueError("Label %s is already in use" % name)

        self.name_to_addr[name] = addr
        try:
            alist = self.addr_to_names[addr]
        except KeyError:
            self.addr_to_names[addr] = [name]
        else:
            if add:
                alist.append(name)
            else:
                alist[0] = name

    def del_label(self, name):
        try:
            addr = self.name_to_addr[name]
        except KeyError:
            pass
        else:
            self.addr_to_names[addr].remove(name)
            if not self.addr_to_names[addr]:
                del self.addr_to_names[addr]
            del self.name_to_addr[name]

    def copy(self):
        o = LabelsPlugin()
        o.addr_to_names = {x: list(y) for x, y in self.addr_to_names.iteritems()}
        o.name_to_addr = dict(self.name_to_addr)


class CommentsPlugin(KPlugin):
    """
    The storage for comments.

    TODO: different kinds of comments? Different comment stores for disassembly vs source?

    :ivar comments:     Mapping from instruction address to comment at that address
    """
    def __init__(self):
        self.comments = {}

    def copy(self):
        o = CommentsPlugin()
        o.comments = dict(self.comments)
