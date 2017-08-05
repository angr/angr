import logging
import struct
l = logging.getLogger("rex.pov_fuzzing.core_loader")


class ParseError(Exception):
    pass


class CoreNote(object):
    """
    This class is used when parsing the NOTES section of a core file.
    """
    n_type_lookup = {
            1: 'NT_PRSTATUS',
            2: 'NT_PRFPREG',
            3: 'NT_PRPSINFO',
            4: 'NT_TASKSTRUCT',
            6: 'NT_AUXV',
            0x53494749: 'NT_SIGINFO',
            0x46494c45: 'NT_FILE',
            0x46e62b7f: 'NT_PRXFPREG'
            }

    def __init__(self, n_type, name, desc):
        self.n_type = n_type
        if n_type in CoreNote.n_type_lookup:
            self.n_type = CoreNote.n_type_lookup[n_type]
        self.name = name
        self.desc = desc

    def __repr__(self):
        return "<Note %s %s %#x>" % (self.name, self.n_type, len(self.desc))


class TinyCore(object):
    def __init__(self, filename):
        self.notes = []
        # siginfo
        self.si_signo = None
        self.si_code = None
        self.si_errno = None

        # prstatus
        self.pr_cursig = None
        self.pr_sigpend = None
        self.pr_sighold = None

        self.pr_pid = None
        self.pr_ppid = None
        self.pr_pgrp = None
        self.pr_sid = None

        self.pr_utime_usec = None
        self.pr_stime_usec = None
        self.pr_cutime_usec = None
        self.pr_cstime_usec = None

        self.registers = None

        self.pr_fpvalid = None
        self.filename = filename

        self.parse()

    def parse(self):
        with open(self.filename, "rb") as f:
            f.seek(28)
            self.ph_off = struct.unpack("<I", f.read(4))[0]
            f.seek(44)
            self.ph_num = struct.unpack("<I", f.read(4))[0]

            f.seek(self.ph_off)
            ph_headers = f.read(self.ph_num*0x20)

            for i in range(self.ph_num):
                off = i*0x20
                p_type_packed = ph_headers[off:off+4]
                # be careful
                if len(p_type_packed) != 4:
                    continue
                p_type = struct.unpack("<I", p_type_packed)[0]
                if p_type == 4:  # note
                    note_offset_packed = ph_headers[off+4:off+8]
                    note_size_packed = ph_headers[off+16:off+20]
                    # be careful
                    if len(note_offset_packed) != 4 or len(note_size_packed) != 4:
                        continue
                    note_offset = struct.unpack("<I", note_offset_packed)[0]
                    note_size = struct.unpack("<I", note_size_packed)[0]
                    if note_size > 0x100000:
                        l.warning("note size > 0x100000")
                        note_size = 0x100000
                    f.seek(note_offset)
                    note_data = f.read(note_size)
                    parsed = self._parse_notes(note_data)
                    if parsed:
                        return
        raise ParseError("failed to find registers in core")


    def _parse_notes(self, note_data):
        """
        This exists, because note parsing in elftools is not good.
        """

        blob = note_data

        note_pos = 0
        while note_pos < len(blob):
            to_unpack = blob[note_pos:note_pos+12]
            if len(to_unpack) != 12:
                break
            name_sz, desc_sz, n_type = struct.unpack("<3I", to_unpack)
            name_sz_rounded = (((name_sz + (4 - 1)) / 4) * 4)
            desc_sz_rounded = (((desc_sz + (4 - 1)) / 4) * 4)
            # description size + the rounded name size + header size
            n_size = desc_sz_rounded + name_sz_rounded + 12

            # name_sz includes the null byte
            name = blob[note_pos+12:note_pos+12+name_sz-1]
            desc = blob[note_pos+12+name_sz_rounded:note_pos+12+name_sz_rounded+desc_sz]

            self.notes.append(CoreNote(n_type, name, desc))
            note_pos += n_size

        # prstatus
        prstatus_list = filter(lambda x: x.n_type == 'NT_PRSTATUS', self.notes)
        if len(prstatus_list) > 1:
            l.warning("multiple prstatus")
        if len(prstatus_list) == 0:
            raise ParseError("no prstatus")
        for prstatus in prstatus_list:
            try:
                self._parse_prstatus(prstatus)
                return True
            except struct.error as e:
                l.warning(e)
        return False

    def _parse_prstatus(self, prstatus):
        """
         Parse out the prstatus, accumulating the general purpose register values. Supports AMD64, X86, ARM, and AARCH64
         at the moment.

         :param prstatus: a note object of type NT_PRSTATUS.
         """

        # extract siginfo from prstatus
        self.si_signo, self.si_code, self.si_errno = struct.unpack("<3I", prstatus.desc[:12])

        # this field is a short, but it's padded to an int
        self.pr_cursig = struct.unpack("<I", prstatus.desc[12:16])[0]

        arch_bytes = 4
        if arch_bytes == 4:
            fmt = "I"
        elif arch_bytes == 8:
            fmt = "Q"
        else:
            raise ParseError("Architecture must have a bitwidth of either 64 or 32")

        self.pr_sigpend, self.pr_sighold = struct.unpack("<" + (fmt * 2), prstatus.desc[16:16 + (2 * arch_bytes)])

        attrs = struct.unpack("<IIII", prstatus.desc[16 + (2 * arch_bytes):16 + (2 * arch_bytes) + (4 * 4)])
        self.pr_pid, self.pr_ppid, self.pr_pgrp, self.pr_sid = attrs

        # parse out the 4 timevals
        pos = 16 + (2 * arch_bytes) + (4 * 4)
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_utime_usec = struct.unpack("<" + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_stime_usec = struct.unpack("<" + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_cutime_usec = struct.unpack("<" + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos + arch_bytes])[0] * 1000
        self.pr_cstime_usec = struct.unpack("<" + fmt, prstatus.desc[pos + arch_bytes:pos + arch_bytes * 2])[0] + usec

        pos += arch_bytes * 2

        # parse out general purpose registers
        rnames = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs', 'gs', 'xxx', 'eip', \
                  'cs', 'eflags', 'esp', 'ss']
        nreg = 17

        regvals = []
        for idx in range(pos, pos + nreg * arch_bytes, arch_bytes):
            regvals.append(struct.unpack("<" + fmt, prstatus.desc[idx:idx + arch_bytes])[0])
        self.registers = dict(zip(rnames, regvals))
        del self.registers['xxx']

        pos += nreg * arch_bytes
        self.pr_fpvalid = struct.unpack("<I", prstatus.desc[pos:pos + 4])[0]
        return True

