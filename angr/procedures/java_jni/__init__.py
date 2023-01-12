import collections
import itertools
import logging
import typing

from archinfo import ArchSoot
from claripy import BVV, StrSubstr

from ...calling_conventions import DefaultCC
from ...sim_procedure import SimProcedure
from ...sim_type import SimTypeFunction
from ...state_plugins.sim_action_object import SimActionObject

l = logging.getLogger("angr.procedures.java_jni")


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
                l.error("Loading of strings with symbolic chars is not supported. " "Character %d is concretized.", i)
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


#
# JNI function table
# => Map all interface function to the name of their corresponding SimProcedure
jni_functions: typing.OrderedDict[str, str] = collections.OrderedDict()
not_implemented = "UnsupportedJNIFunction"

# Reserved Entries
jni_functions["reserved0"] = not_implemented
jni_functions["reserved1"] = not_implemented
jni_functions["reserved2"] = not_implemented
jni_functions["reserved3"] = not_implemented

# Version Information
jni_functions["GetVersion"] = "GetVersion"

# Class and Interface Operations
jni_functions["DefineClass"] = not_implemented
jni_functions["FindClass"] = "FindClass"
jni_functions["FromReflectedMethod"] = not_implemented
jni_functions["FromReflectedField"] = not_implemented
jni_functions["ToReflectedMethod"] = not_implemented
jni_functions["GetSuperclass"] = "GetSuperclass"
jni_functions["IsAssignableFrom"] = not_implemented
jni_functions["ToReflectedField"] = not_implemented

# Exceptions
jni_functions["Throw"] = not_implemented
jni_functions["ThrowNew"] = not_implemented
jni_functions["ExceptionOccurred"] = not_implemented
jni_functions["ExceptionDescribe"] = not_implemented
jni_functions["ExceptionClear"] = not_implemented
jni_functions["FatalError"] = not_implemented

# Global and Local References
jni_functions["PushLocalFrame"] = not_implemented
jni_functions["PopLocalFrame"] = not_implemented
jni_functions["NewGlobalRef"] = "NewGlobalRef"
jni_functions["DeleteGlobalRef"] = "DeleteGlobalRef"
jni_functions["DeleteLocalRef"] = "DeleteLocalRef"

# Object Operations
jni_functions["IsSameObject"] = "IsSameObject"
jni_functions["NewLocalRef"] = "NewLocalRef"
jni_functions["EnsureLocalCapacity"] = not_implemented
jni_functions["AllocObject"] = "AllocObject"
jni_functions["NewObject"] = "NewObject"
jni_functions["NewObjectV"] = not_implemented
jni_functions["NewObjectA"] = not_implemented
jni_functions["GetObjectClass"] = "GetObjectClass"
jni_functions["IsInstanceOf"] = "IsInstanceOf"

# Instance Method Calls
jni_functions["GetMethodID"] = "GetMethodID"
jni_functions["CallObjectMethod"] = "CallObjectMethod"
jni_functions["CallObjectMethodV"] = not_implemented
jni_functions["CallObjectMethodA"] = "CallObjectMethodA"
jni_functions["CallBooleanMethod"] = "CallBooleanMethod"
jni_functions["CallBooleanMethodV"] = not_implemented
jni_functions["CallBooleanMethodA"] = "CallBooleanMethodA"
jni_functions["CallByteMethod"] = "CallByteMethod"
jni_functions["CallByteMethodV"] = not_implemented
jni_functions["CallByteMethodA"] = "CallByteMethodA"
jni_functions["CallCharMethod"] = "CallCharMethod"
jni_functions["CallCharMethodV"] = not_implemented
jni_functions["CallCharMethodA"] = "CallCharMethodA"
jni_functions["CallShortMethod"] = "CallShortMethod"
jni_functions["CallShortMethodV"] = not_implemented
jni_functions["CallShortMethodA"] = "CallShortMethodA"
jni_functions["CallIntMethod"] = "CallIntMethod"
jni_functions["CallIntMethodV"] = not_implemented
jni_functions["CallIntMethodA"] = "CallIntMethodA"
jni_functions["CallLongMethod"] = "CallLongMethod"
jni_functions["CallLongMethodV"] = not_implemented
jni_functions["CallLongMethodA"] = "CallLongMethodA"
jni_functions["CallFloatMethod"] = not_implemented
jni_functions["CallFloatMethodV"] = not_implemented
jni_functions["CallFloatMethodA"] = not_implemented
jni_functions["CallDoubleMethod"] = not_implemented
jni_functions["CallDoubleMethodV"] = not_implemented
jni_functions["CallDoubleMethodA"] = not_implemented
jni_functions["CallVoidMethod"] = "CallVoidMethod"
jni_functions["CallVoidMethodV"] = not_implemented
jni_functions["CallVoidMethodA"] = "CallVoidMethodA"

# Calling Instance Methods of a Superclass
jni_functions["CallNonvirtualObjectMethod"] = "CallNonvirtualObjectMethod"
jni_functions["CallNonvirtualObjectMethodV"] = not_implemented
jni_functions["CallNonvirtualObjectMethodA"] = "CallNonvirtualObjectMethodA"
jni_functions["CallNonvirtualBooleanMethod"] = "CallNonvirtualBooleanMethod"
jni_functions["CallNonvirtualBooleanMethodV"] = not_implemented
jni_functions["CallNonvirtualBooleanMethodA"] = "CallNonvirtualBooleanMethodA"
jni_functions["CallNonvirtualByteMethod"] = "CallNonvirtualByteMethod"
jni_functions["CallNonvirtualByteMethodV"] = not_implemented
jni_functions["CallNonvirtualByteMethodA"] = "CallNonvirtualByteMethodA"
jni_functions["CallNonvirtualCharMethod"] = "CallNonvirtualCharMethod"
jni_functions["CallNonvirtualCharMethodV"] = not_implemented
jni_functions["CallNonvirtualCharMethodA"] = "CallNonvirtualCharMethodA"
jni_functions["CallNonvirtualShortMethod"] = "CallNonvirtualShortMethod"
jni_functions["CallNonvirtualShortMethodV"] = not_implemented
jni_functions["CallNonvirtualShortMethodA"] = "CallNonvirtualShortMethodA"
jni_functions["CallNonvirtualIntMethod"] = "CallNonvirtualIntMethod"
jni_functions["CallNonvirtualIntMethodV"] = not_implemented
jni_functions["CallNonvirtualIntMethodA"] = "CallNonvirtualIntMethodA"
jni_functions["CallNonvirtualLongMethod"] = "CallNonvirtualLongMethod"
jni_functions["CallNonvirtualLongMethodV"] = not_implemented
jni_functions["CallNonvirtualLongMethodA"] = "CallNonvirtualLongMethodA"
jni_functions["CallNonvirtualFloatMethod"] = not_implemented
jni_functions["CallNonvirtualFloatMethodV"] = not_implemented
jni_functions["CallNonvirtualFloatMethodA"] = not_implemented
jni_functions["CallNonvirtualDoubleMethod"] = not_implemented
jni_functions["CallNonvirtualDoubleMethodV"] = not_implemented
jni_functions["CallNonvirtualDoubleMethodA"] = not_implemented
jni_functions["CallNonvirtualVoidMethod"] = "CallNonvirtualVoidMethod"
jni_functions["CallNonvirtualVoidMethodV"] = not_implemented
jni_functions["CallNonvirtualVoidMethodA"] = "CallNonvirtualVoidMethodA"

# Instance Field Access
jni_functions["GetFieldID"] = "GetFieldID"
jni_functions["GetObjectField"] = "GetObjectField"
jni_functions["GetBooleanField"] = "GetBooleanField"
jni_functions["GetByteField"] = "GetByteField"
jni_functions["GetCharField"] = "GetCharField"
jni_functions["GetShortField"] = "GetShortField"
jni_functions["GetIntField"] = "GetIntField"
jni_functions["GetLongField"] = "GetLongField"
jni_functions["GetFloatField"] = not_implemented
jni_functions["GetDoubleField"] = not_implemented
jni_functions["SetObjectField"] = "SetField"
jni_functions["SetBooleanField"] = "SetField"
jni_functions["SetByteField"] = "SetField"
jni_functions["SetCharField"] = "SetField"
jni_functions["SetShortField"] = "SetField"
jni_functions["SetIntField"] = "SetField"
jni_functions["SetLongField"] = "SetField"
jni_functions["SetFloatField"] = not_implemented
jni_functions["SetDoubleField"] = not_implemented

# Static Method Calls
jni_functions["GetStaticMethodID"] = "GetMethodID"
jni_functions["CallStaticObjectMethod"] = "CallStaticObjectMethod"
jni_functions["CallStaticObjectMethodV"] = not_implemented
jni_functions["CallStaticObjectMethodA"] = "CallStaticObjectMethodA"
jni_functions["CallStaticBooleanMethod"] = "CallStaticBooleanMethod"
jni_functions["CallStaticBooleanMethodV"] = not_implemented
jni_functions["CallStaticBooleanMethodA"] = "CallStaticBooleanMethodA"
jni_functions["CallStaticByteMethod"] = "CallStaticByteMethod"
jni_functions["CallStaticByteMethodV"] = not_implemented
jni_functions["CallStaticByteMethodA"] = "CallStaticByteMethodA"
jni_functions["CallStaticCharMethod"] = "CallStaticCharMethod"
jni_functions["CallStaticCharMethodV"] = not_implemented
jni_functions["CallStaticCharMethodA"] = "CallStaticCharMethodA"
jni_functions["CallStaticShortMethod"] = "CallStaticShortMethod"
jni_functions["CallStaticShortMethodV"] = not_implemented
jni_functions["CallStaticShortMethodA"] = "CallStaticShortMethodA"
jni_functions["CallStaticIntMethod"] = "CallStaticIntMethod"
jni_functions["CallStaticIntMethodV"] = not_implemented
jni_functions["CallStaticIntMethodA"] = "CallStaticIntMethodA"
jni_functions["CallStaticLongMethod"] = "CallStaticLongMethod"
jni_functions["CallStaticLongMethodV"] = not_implemented
jni_functions["CallStaticLongMethodA"] = "CallStaticLongMethodA"
jni_functions["CallStaticFloatMethod"] = not_implemented
jni_functions["CallStaticFloatMethodV"] = not_implemented
jni_functions["CallStaticFloatMethodA"] = not_implemented
jni_functions["CallStaticDoubleMethod"] = not_implemented
jni_functions["CallStaticDoubleMethodV"] = not_implemented
jni_functions["CallStaticDoubleMethodA"] = not_implemented
jni_functions["CallStaticVoidMethod"] = "CallStaticVoidMethod"
jni_functions["CallStaticVoidMethodV"] = not_implemented
jni_functions["CallStaticVoidMethodA"] = "CallStaticVoidMethodA"

# Static Field Access
jni_functions["GetStaticFieldID"] = "GetFieldID"
jni_functions["GetStaticObjectField"] = "GetStaticObjectField"
jni_functions["GetStaticBooleanField"] = "GetStaticBooleanField"
jni_functions["GetStaticByteField"] = "GetStaticByteField"
jni_functions["GetStaticCharField"] = "GetStaticCharField"
jni_functions["GetStaticShortField"] = "GetStaticShortField"
jni_functions["GetStaticIntField"] = "GetStaticIntField"
jni_functions["GetStaticLongField"] = "GetStaticLongField"
jni_functions["GetStaticFloatField"] = not_implemented
jni_functions["GetStaticDoubleField"] = not_implemented
jni_functions["SetStaticObjectField"] = "SetStaticField"
jni_functions["SetStaticBooleanField"] = "SetStaticField"
jni_functions["SetStaticByteField"] = "SetStaticField"
jni_functions["SetStaticCharField"] = "SetStaticField"
jni_functions["SetStaticShortField"] = "SetStaticField"
jni_functions["SetStaticIntField"] = "SetStaticField"
jni_functions["SetStaticLongField"] = "SetStaticField"
jni_functions["SetStaticFloatField"] = not_implemented
jni_functions["SetStaticDoubleField"] = not_implemented

# String Operations
jni_functions["NewString"] = not_implemented
jni_functions["GetStringLength"] = not_implemented
jni_functions["GetStringChars"] = not_implemented
jni_functions["ReleaseStringChars"] = not_implemented
jni_functions["NewStringUTF"] = "NewStringUTF"
jni_functions["GetStringUTFLength"] = "GetStringUTFLength"
jni_functions["GetStringUTFChars"] = "GetStringUTFChars"
jni_functions["ReleaseStringUTFChars"] = "ReleaseStringUTFChars"

# Array Operations
jni_functions["GetArrayLength"] = "GetArrayLength"
jni_functions["NewObjectArray"] = "NewObjectArray"
jni_functions["GetObjectArrayElement"] = "GetObjectArrayElement"
jni_functions["SetObjectArrayElement"] = "SetObjectArrayElement"
jni_functions["NewBooleanArray"] = "NewBooleanArray"
jni_functions["NewByteArray"] = "NewByteArray"
jni_functions["NewCharArray"] = "NewCharArray"
jni_functions["NewShortArray"] = "NewShortArray"
jni_functions["NewIntArray"] = "NewIntArray"
jni_functions["NewLongArray"] = "NewLongArray"
jni_functions["NewFloatArray"] = not_implemented
jni_functions["NewDoubleArray"] = not_implemented
jni_functions["GetBooleanArrayElements"] = "GetArrayElements"
jni_functions["GetByteArrayElements"] = "GetArrayElements"
jni_functions["GetCharArrayElements"] = "GetArrayElements"
jni_functions["GetShortArrayElements"] = "GetArrayElements"
jni_functions["GetIntArrayElements"] = "GetArrayElements"
jni_functions["GetLongArrayElements"] = "GetArrayElements"
jni_functions["GetFloatArrayElements"] = not_implemented
jni_functions["GetDoubleArrayElements"] = not_implemented
jni_functions["ReleaseBooleanArrayElements"] = not_implemented
jni_functions["ReleaseByteArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseCharArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseShortArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseIntArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseLongArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseFloatArrayElements"] = not_implemented
jni_functions["ReleaseDoubleArrayElements"] = not_implemented
jni_functions["GetBooleanArrayRegion"] = "GetArrayRegion"
jni_functions["GetByteArrayRegion"] = "GetArrayRegion"
jni_functions["GetCharArrayRegion"] = "GetArrayRegion"
jni_functions["GetShortArrayRegion"] = "GetArrayRegion"
jni_functions["GetIntArrayRegion"] = "GetArrayRegion"
jni_functions["GetLongArrayRegion"] = "GetArrayRegion"
jni_functions["GetFloatArrayRegion"] = not_implemented
jni_functions["GetDoubleArrayRegion"] = not_implemented
jni_functions["SetBooleanArrayRegion"] = "SetArrayRegion"
jni_functions["SetByteArrayRegion"] = "SetArrayRegion"
jni_functions["SetCharArrayRegion"] = "SetArrayRegion"
jni_functions["SetShortArrayRegion"] = "SetArrayRegion"
jni_functions["SetIntArrayRegion"] = "SetArrayRegion"
jni_functions["SetLongArrayRegion"] = "SetArrayRegion"
jni_functions["SetFloatArrayRegion"] = not_implemented
jni_functions["SetDoubleArrayRegion"] = not_implemented

# Native Method Registration
jni_functions["RegisterNatives"] = not_implemented
jni_functions["UnregisterNatives"] = not_implemented

# Monitor Operations
jni_functions["MonitorEnter"] = not_implemented
jni_functions["MonitorExit"] = not_implemented

# JavaVM Interface
jni_functions["GetJavaVM"] = not_implemented

# Misc
jni_functions["GetStringRegion"] = not_implemented
jni_functions["GetStringUTFRegion"] = not_implemented
jni_functions["GetPrimitiveArrayCritical"] = "GetArrayElements"
jni_functions["ReleasePrimitiveArrayCritical"] = "ReleaseArrayElements"
jni_functions["GetStringCritical"] = not_implemented
jni_functions["ReleaseStringCritical"] = not_implemented
jni_functions["NewWeakGlobalRef"] = "NewGlobalRef"
jni_functions["DeleteWeakGlobalRef"] = "DeleteGlobalRef"
jni_functions["ExceptionCheck"] = not_implemented
jni_functions["NewDirectByteBuffer"] = not_implemented
jni_functions["GetDirectBufferAddress"] = not_implemented
jni_functions["GetDirectBufferCapacity"] = not_implemented
jni_functions["GetObjectRefType"] = not_implemented
