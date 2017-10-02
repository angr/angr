
class MemoryData(object):
    """
    MemoryData describes the syntactic contents of single address of memory along with a set of references to this
    address (when not from previous instruction).
    """
    def __init__(self, address, size, sort, irsb, irsb_addr, stmt, stmt_idx, pointer_addr=None, max_size=None,
                 insn_addr=None):
        self.address = address
        self.size = size
        self.sort = sort
        self.irsb = irsb
        self.irsb_addr = irsb_addr
        self.stmt = stmt
        self.stmt_idx = stmt_idx
        self.insn_addr = insn_addr

        self.max_size = max_size
        self.pointer_addr = pointer_addr

        self.content = None  # optional

        self.refs = set()
        if irsb_addr and stmt_idx:
            self.refs.add((irsb_addr, stmt_idx, insn_addr))

    def __repr__(self):
        return "\\%#x, %s, %s/" % (self.address,
                                   "%d bytes" % self.size if self.size is not None else "size unknown",
                                   self.sort
                                   )

    def copy(self):
        """
        Make a copy of the MemoryData.

        :return: A copy of the MemoryData instance.
        :rtype: angr.analyses.cfg_fast.MemoryData
        """
        s = MemoryData(self.address, self.size, self.sort, self.irsb, self.irsb_addr, self.stmt, self.stmt_idx,
                       pointer_addr=self.pointer_addr, max_size=self.max_size, insn_addr=self.insn_addr
                       )
        s.refs = self.refs.copy()

        return s

    def add_ref(self, irsb_addr, stmt_idx, insn_addr):
        """
        Add a reference from code to this memory data.

        :param int irsb_addr: Address of the basic block.
        :param int stmt_idx: ID of the statement referencing this data entry.
        :param int insn_addr: Address of the instruction referencing this data entry.
        :return: None
        """

        ref = (irsb_addr, stmt_idx, insn_addr)
        if ref not in self.refs:
            self.refs.add(ref)


class MemoryDataReference(object):
    def __init__(self, ref_ins_addr):
        self.ref_ins_addr = ref_ins_addr
