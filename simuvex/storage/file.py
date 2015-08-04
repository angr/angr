from ..plugins.plugin import SimStatePlugin
from ..s_action_object import SimActionObject

import logging
l = logging.getLogger("simuvex.storage.file")

# TODO: symbolic file positions
import itertools
file_counter = itertools.count()

class Flags: # pylint: disable=W0232,
    O_RDONLY = 0
    O_WRTONLY = 1
    O_RDWR = 2
    O_APPEND = 4096
    O_ASYNC = 64
    O_CLOEXEC = 512
    # TODO mode for this flag
    O_CREAT = 256
    O_DIRECT = 262144
    O_DIRECTORY = 2097152
    O_EXCL = 2048
    O_LARGEFILE = 1048576
    O_NOATIME = 16777216
    O_NOCTTY = 1024
    O_NOFOLLOW = 4194304
    O_NONBLOCK = 8192
    O_NODELAY = 8192
    O_SYNC = 67174400
    O_TRUNC = 1024


def _deps_unpack(a):
    if isinstance(a, SimActionObject):
        return a.ast, a.reg_deps, a.tmp_deps
    else:
        return a, None, None


class SimFile(SimStatePlugin):
    # Creates a SimFile
    def __init__(self, name, mode):
        super(SimFile, self).__init__()
        self.name = name
        self.mode = mode
        self.pos = 0

        # TODO: handle symbolic names, special cases for stdin/out/err
        # TODO: read content for existing files

    @property
    def read_pos(self):
        return self.pos

    @read_pos.setter
    def read_pos(self, val):
        self.pos = val

    @property
    def write_pos(self):
        return self.pos

    @write_pos.setter
    def write_pos(self, val):
        self.pos = val

    def _read(self, length, pos, dst_addr=None):
        raise NotImplementedError("SimFile._read must be implemented by subclass")

    def read(self, length, pos=None, dst_addr=None):
        '''
        Reads some data from the current (or provided) position of the file.
        If dst_addr is specified, write it to that address.
        '''
        if pos is None:
            load_data = self._read(self.read_pos, length, dst_addr=dst_addr)
            self.read_pos += _deps_unpack(length)[0]
        else:
            load_data = self._read(pos, length, dst_addr=dst_addr)

        return load_data

    def _write(self, content, length, pos):
        raise NotImplementedError("SimFile._write must be implemented by subclass")

    # Writes some data to the current position of the file.
    def write(self, content, length, pos=None):
        # TODO: error handling
        # TODO: symbolic length?
        if pos is None:
            self._write(self.write_pos, content, length)
            self.write_pos += _deps_unpack(length)[0]
        else:
            self._write(pos, content, length)

        return length

    # Seeks to a position in the file.
    def seek(self, where):
        raise NotImplementedError("SimFile.seek must be implemented by subclass")

    # Copies the SimFile object.
    def copy(self):
        raise NotImplementedError("SimFile.copy must be implemented by subclass")

    def all_bytes(self):
        raise NotImplementedError("SimFile.all_bytes must be implemented by subclass")

    # Merges the SimFile object with others
    def merge(self, others, merge_flag, flag_values):
        raise NotImplementedError("SimFile.merge must be implemented by subclass")


class SimSymbolicFile(SimFile):
    def __init__(self, name, mode, pos=0, content=None):
        super(SimSymbolicFile, self).__init__(name, mode)
        self.pos = pos
        self.content = SimSymbolicMemory(memory_id="file_%s_%d" % (name, file_counter.next())) if content is None else content

    def set_state(self, st):
        super(SimSymbolicFile, self).set_state(st)
        self.content.set_state(st)

    def _read(self, pos, length, dst_addr=None):
        if dst_addr is None:
            return self.content.load(pos, length)
        else:
            return self.content.copy_contents(dst_addr, pos, length, dst_memory=self.state.memory)

    def _write(self, pos, content, length):
        # TODO: something about length
        self.content.store(pos, content)

    def seek(self, where):
        self.pos = where

    def copy(self):
        return SimSymbolicFile(self.name, self.mode, pos=self.pos, content=self.content.copy())

    def all_bytes(self):
        indexes = self.content.mem.keys()
        if len(indexes) == 0:
            raise SimFileError('no content in file %s' % self.name)

        min_idx = min(indexes)
        max_idx = max(indexes)
        buff = [ ]
        for i in range(min_idx, max_idx+1):
            buff.append(self.content.load(i, 1))
        return self.state.se.Concat(*buff)

    def merge(self, others, merge_flag, flag_values):
        if not all(isinstance(oth, SimSymbolicFile) for oth in others):
            raise SimMergeError("merging files of different types is not supported")

        all_files = list(others) + [ self ]

        if len(set(o.pos for o in all_files)) > 1:
            l.warning("Cheap HACK to support multiple file positions in a merge.")
            # self.pos = max(o.pos for o in all_files)
            # max cannot be used as file positions might be symbolic.
            max_pos = None
            for o in all_files:
                if max_pos is not None:
                    comp = self.state.se.simplify(max_pos >= o.pos)
                    if self.state.se.symbolic(comp):
                        import ipdb; ipdb.set_trace()
                        raise SimMergeError("merging file positions with symbolic max position is not ye supported (TODO)")

                    max_pos = o.pos if self.state.se.is_false(comp) else max_pos
                else:
                    max_pos = o.pos
            self.pos = max_pos

        #if len(set(o.name for o in all_files)) > 1:
        #   raise SimMergeError("merging file names is not yet supported (TODO)")

        #if len(set(o.mode for o in all_files)) > 1:
        #   raise SimMergeError("merging modes is not yet supported (TODO)")

        return self.content.merge([ o.content for o in others ], merge_flag, flag_values)


class SimConcreteFile(SimFile):
    def __init__(self, name, mode, content, pos=0, tag=False):
        super(SimConcreteFile, self).__init__(name, mode)
        self.pos = pos
        self.content = content
        self.tag = tag

    def _read(self, pos, length, dst_addr=None):
        # worry about symbolic later...
        pos = self.state.se.any_int(pos)
        length = self.state.se.any_int(length)
        data = self.content[pos:pos+length]
        data += '\x00'*(length - len(data))
        if self.tag:
            parts = (self.state.se.BVV(ord(c), 8, name=('%s_%d' % (self.name, pos + i)))
                     for (i, c)
                     in enumerate(data))
            bv_data = self.state.se.Concat(*parts)
        else:
            bv_data = self.state.BVV(data)

        if dst_addr is None:
            return bv_data
        else:
            self.state.memory.store(dst_addr, bv_data, size=length)
            return bv_data      # is this necessary?

    def _write(self, pos, content, length):
        data = self._read(pos, length)
        self.state.add_constraints(content == data)

    def copy(self):
        return SimConcreteFile(self.name, self.mode, self.content, pos=self.pos, tag=self.tag)

    def all_bytes(self):
        return self._read(0, len(self.content))


class SimPCAPFile(SimFile):
    def __init__(self, name, mode, pcap, pos=0):
        super(SimPCAPFile, self).__init__(name, mode, pos=pos)


from ..plugins.symbolic_memory import SimSymbolicMemory
from ..s_errors import SimMergeError, SimFileError
