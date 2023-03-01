import itertools
import logging
import typing

from archinfo import ArchSoot
from claripy import BVV, StrSubstr

from angr.calling_conventions import DefaultCC
from angr.sim_procedure import SimProcedure
from angr.sim_type import SimTypeFunction
from angr.state_plugins.sim_action_object import SimActionObject

l = logging.getLogger(__name__)


class JNISimProcedure(SimProcedure):
    """
    Base SimProcedure class for JNI interface functions.
    """

    # Java type of return value
    return_ty: typing.Optional[str] = None

    # jboolean constants
    JNI_TRUE = 1
    JNI_FALSE = 0

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        # Setup a SimCC using the correct type for the return value
        if not self.return_ty:
            raise ValueError("Classes implementing JNISimProcedure's must set the return type.")
        elif self.return_ty != "void":
            prototype = SimTypeFunction(
                args=self.prototype.args, returnty=state.project.simos.get_native_type(self.return_ty)
            )
            self.cc = DefaultCC[state.arch.name](state.arch)
            self.prototype = prototype
        super().execute(state, successors, arguments, ret_to)

    #
    # Memory
    #

    def _allocate_native_memory(self, size):
        return self.state.project.loader.extern_object.allocate(size=size)

    def _store_in_native_memory(self, data, data_type, addr=None):
        """
        Store in native memory.

        :param data:      Either a single value or a list.
                          Lists get interpreted as an array.
        :param data_type: Java type of the element(s).
        :param addr:      Native store address.
                          If not set, native memory is allocated.
        :return:          Native addr of the stored data.
        """
        # check if addr is symbolic
        if addr is not None and self.state.solver.symbolic(addr):
            raise NotImplementedError("Symbolic addresses are not supported.")
        # lookup native size of the type
        type_size = ArchSoot.sizeof[data_type]
        native_memory_endness = self.state.arch.memory_endness
        # store single value
        if isinstance(data, int):
            if addr is None:
                addr = self._allocate_native_memory(size=type_size // 8)
            value = self.state.solver.BVV(data, type_size)
            self.state.memory.store(addr, value, endness=native_memory_endness)
        # store array
        elif isinstance(data, list):
            if addr is None:
                addr = self._allocate_native_memory(size=type_size * len(data) // 8)
            for idx, value in enumerate(data):
                memory_addr = addr + idx * type_size // 8
                self.state.memory.store(memory_addr, value, endness=native_memory_endness)
        # return native addr
        return addr

    def _load_from_native_memory(self, addr, data_type=None, data_size=None, no_of_elements=1, return_as_list=False):
        """
        Load from native memory.

        :param addr:            Native load address.
        :param data_type:       Java type of elements.
                                If set, all loaded elements are casted to this type.
        :param data_size:       Size of each element.
                                If not set, size is determined based on the given type.
        :param no_of_elements:  Number of elements to load.
        :param return_as_list:  Whether to wrap a single element in a list.
        :return:                The value or a list of loaded element(s).
        """
        # check if addr is symbolic
        if addr is not None and self.state.solver.symbolic(addr):
            raise NotImplementedError("Symbolic addresses are not supported.")
        # if data size is not set, derive it from the type
        if not data_size:
            if data_type:
                data_size = ArchSoot.sizeof[data_type] // 8
            else:
                raise ValueError("Cannot determine the data size w/o a type.")
        native_memory_endness = self.state.arch.memory_endness
        # load elements
        values = []
        for i in range(no_of_elements):
            value = self.state.memory.load(addr + i * data_size, size=data_size, endness=native_memory_endness)
            if data_type:
                value = self.state.project.simos.cast_primitive(self.state, value=value, to_type=data_type)
            values.append(value)
        # return element(s)
        if no_of_elements == 1 and not return_as_list:
            return values[0]
        else:
            return values

    def _load_string_from_native_memory(self, addr_):
        """
        Load zero terminated UTF-8 string from native memory.

        :param addr_: Native load address.
        :return:      Loaded string.
        """
        # check if addr is symbolic
        if self.state.solver.symbolic(addr_):
            l.error(
                "Loading strings from symbolic addresses is not implemented. "
                "Continue execution with an empty string."
            )
            return ""
        addr = self.state.solver.eval(addr_)

        # load chars one by one
        chars = []
        for i in itertools.count():
            str_byte = self.state.memory.load(addr + i, size=1)
            if self.state.solver.symbolic(str_byte):
                l.error("Loading of strings with symbolic chars is not supported. Character %d is concretized.", i)
            str_byte = self.state.solver.eval(str_byte)
            if str_byte == 0:
                break
            chars.append(chr(str_byte))

        return "".join(chars)

    def _store_string_in_native_memory(self, string, addr=None):
        """
        Store given string UTF-8 encoded and zero terminated in native memory.

        :param str string:  String
        :param addr:        Native store address.
                            If not set, native memory is allocated.
        :return:            Native address of the string.
        """
        if addr is None:
            addr = self._allocate_native_memory(size=len(string) + 1)
        else:
            # check if addr is symbolic
            if self.state.solver.symbolic(addr):
                l.error(
                    "Storing strings at symbolic addresses is not implemented. "
                    "Continue execution with concretized address."
                )
            addr = self.state.solver.eval(addr)

        # warn if string is symbolic
        if self.state.solver.symbolic(string):
            l.warning(
                "Support for symbolic strings, passed to native code, is limited. "
                "String will get concretized after `ReleaseStringUTFChars` is called."
            )

        # store chars one by one
        str_len = len(string) // 8
        for idx in range(str_len):
            str_byte = StrSubstr(idx, 1, string)
            self.state.memory.store(addr + idx, str_byte)

        # store terminating zero
        self.state.memory.store(len(string), BVV(0, 8))

        return addr

    #
    # MISC
    #

    def _normalize_array_idx(self, idx):
        """
        In Java, all array indices are represented by a 32 bit integer and
        consequently we are using in the Soot engine a 32bit bitvector for this.
        This function normalize the given index to follow this "convention".

        :return: Index as a 32bit bitvector.
        """
        if isinstance(idx, SimActionObject):
            idx = idx.to_claripy()
        if self.arch.memory_endness == "Iend_LE":
            return idx.reversed.get_bytes(index=0, size=4).reversed
        else:
            return idx.get_bytes(index=0, size=4)
