
from ...sim_procedure import SimProcedure
from ...sim_type import SimTypeFunction
from ...calling_conventions import DefaultCC
from archinfo import ArchSoot
from ...state_plugins.sim_action_object import SimActionObject


class JNISimProcedure(SimProcedure):

    return_ty = None

    def __init__(self, **kwargs):
        super(JNISimProcedure, self).__init__(**kwargs)

        # jboolean constants 
        self.JNI_TRUE = 1
        self.JNI_FALSE = 0

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        # Setup a SimCC using the correct type for the return value
        if self.return_ty is None:
            raise ValueError("Classes implementing JNISimProcedure's must set the return type.")
        elif self.return_ty is not 'void':
            func_ty = SimTypeFunction(args=[], returnty=state.project.simos.get_native_type(self.return_ty))
            self.cc = DefaultCC[state.arch.name](state.arch, func_ty=func_ty)
        super(JNISimProcedure, self).execute(state, successors, arguments, ret_to)


    #
    # Memory
    #

    def allocate_native_memory(self, size):
        return self.state.project.loader.extern_object.allocate(size=size)

    def store_in_native_memory(self, data, data_type, addr=None):
        """
        
        list resembling arrays
        -> type is base_type of array elements

        """

        if addr is not None and self.state.solver.symbolic(addr):
            print "symbolic addr"

        type_size = ArchSoot.sizeof[data_type]
        native_memory_endness = self.state.arch.memory_endness

        if isinstance(data, int):
            if addr is None:
                addr = self.allocate_native_memory(size=type_size/8)
            value = self.state.solver.BVV(data, type_size)
            self.state.memory.store(addr, value, endness=native_memory_endness)

        elif isinstance(data, list):
            if addr is None:
                addr = self.allocate_native_memory(size=type_size*len(data))
            for idx, value in enumerate(data):
                memory_addr = addr+idx*type_size/8
                self.state.memory.store(memory_addr, value, endness=native_memory_endness)

        return addr

    def load_from_native_memory(self, addr, value_type, no_of_elements=1):

        if addr is not None and self.state.solver.symbolic(addr):
            print "symbolic addr"

        type_size = ArchSoot.sizeof[value_type]/8

        values = [] 
        for i in range(no_of_elements):
            value_uncasted = self.state.memory.load(addr + i*type_size, size=type_size, endness="Iend_LE")
            value = self.state.project.simos.cast_primitive(value=value_uncasted, 
                                                            to_type=value_type)
            values.append(value)

        if no_of_elements == 1:
            return values[0]
        else:
            return values

    #
    # MISC
    #

    def _normalize_array_idx(self, idx):
        """
        In Java, all array indices are represented by a 32 bit integer and consequently we are 
        using in the Soot engine a 32bit bitvector for this. This function normalize the given
        index to follow this "convention".
        :return: Index as a 32bit bitvector.
        """
        if isinstance(idx, SimActionObject):
            idx = idx.to_claripy()
        if self.arch.memory_endness == "Iend_LE":
            return idx.reversed.get_bytes(index=0, size=4).reversed
        else:
            return idx.get_bytes(index=0, size=4)

# Dictionary containing all functions from the JNI Native Interface struct
# All entries with None are replaced with a NotImplemented SimProcedure
jni_functions = [
    None, 		# reserved0
    None, 		# reserved1
    None, 		# reserved2
    None, 		# reserved3
    "GetVersion", # GetVersion
    None, 		# DefineClass
    None, 		# FindClass
    None, 		# FromReflectedMethod
    None, 		# FromReflectedField
    None, 		# ToReflectedMethod
    None, 		# GetSuperclass
    None, 		# IsAssignableFrom
    None, 		# ToReflectedField
    None, 		# Throw
    None, 		# ThrowNew
    None, 		# ExceptionOccurred
    None, 		# ExceptionDescribe
    None, 		# ExceptionClear
    None, 		# FatalError
    None, 		# PushLocalFrame
    None, 		# PopLocalFrame
    None, 		# NewGlobalRef
    None, 		# DeleteGlobalRef
    None, 		# DeleteLocalRef
    None, 		# IsSameObject
    None, 		# NewLocalRef
    None, 		# EnsureLocalCapacity
    None, 		# AllocObject
    None, 		# NewObject
    None, 		# NewObjectV
    None, 		# NewObjectA
    "GetObjectClass", # GetObjectClass
    None, 		# IsInstanceOf
    None, 		# GetMethodID
    None, 		# CallObjectMethod
    None, 		# CallObjectMethodV
    None, 		# CallObjectMethodA
    None, 		# CallBooleanMethod
    None, 		# CallBooleanMethodV
    None, 		# CallBooleanMethodA
    None, 		# CallByteMethod
    None, 		# CallByteMethodV
    None, 		# CallByteMethodA
    None, 		# CallCharMethod
    None, 		# CallCharMethodV
    None, 		# CallCharMethodA
    None, 		# CallShortMethod
    None, 		# CallShortMethodV
    None, 		# CallShortMethodA
    None, 		# CallIntMethod
    None, 		# CallIntMethodV
    None, 		# CallIntMethodA
    None, 		# CallLongMethod
    None, 		# CallLongMethodV
    None, 		# CallLongMethodA
    None, 		# CallFloatMethod
    None, 		# CallFloatMethodV
    None, 		# CallFloatMethodA
    None, 		# CallDoubleMethod
    None, 		# CallDoubleMethodV
    None, 		# CallDoubleMethodA
    None, 		# CallVoidMethod
    None, 		# CallVoidMethodV
    None, 		# CallVoidMethodA
    None, 		# CallNonvirtualObjectMethod
    None, 		# CallNonvirtualObjectMethodV
    None, 		# CallNonvirtualObjectMethodA
    None, 		# CallNonvirtualBooleanMethod
    None, 		# CallNonvirtualBooleanMethodV
    None, 		# CallNonvirtualBooleanMethodA
    None, 		# CallNonvirtualByteMethod
    None, 		# CallNonvirtualByteMethodV
    None, 		# CallNonvirtualByteMethodA
    None, 		# CallNonvirtualCharMethod
    None, 		# CallNonvirtualCharMethodV
    None, 		# CallNonvirtualCharMethodA
    None, 		# CallNonvirtualShortMethod
    None, 		# CallNonvirtualShortMethodV
    None, 		# CallNonvirtualShortMethodA
    None, 		# CallNonvirtualIntMethod
    None, 		# CallNonvirtualIntMethodV
    None, 		# CallNonvirtualIntMethodA
    None, 		# CallNonvirtualLongMethod
    None, 		# CallNonvirtualLongMethodV
    None, 		# CallNonvirtualLongMethodA
    None, 		# CallNonvirtualFloatMethod
    None, 		# CallNonvirtualFloatMethodV
    None, 		# CallNonvirtualFloatMethodA
    None, 		# CallNonvirtualDoubleMethod
    None, 		# CallNonvirtualDoubleMethodV
    None, 		# CallNonvirtualDoubleMethodA
    None, 		# CallNonvirtualVoidMethod
    None, 		# CallNonvirtualVoidMethodV
    None, 		# CallNonvirtualVoidMethodA
    "GetFieldID", # GetFieldID
    "GetObjectField", # GetObjectField
    "GetBooleanField", # GetBooleanField
    "GetByteField", # GetByteField
    "GetCharField", # GetCharField
    "GetShortField", # GetShortField
    "GetIntField", # GetIntField
    "GetLongField", # GetLongField
    None, 		# GetFloatField
    None, 		# GetDoubleField
    None, 		# SetObjectField
    None, 		# SetBooleanField
    None, 		# SetByteField
    None, 		# SetCharField
    None, 		# SetShortField
    None, 		# SetIntField
    None, 		# SetLongField
    None, 		# SetFloatField
    None, 		# SetDoubleField
    None, 		# GetStaticMethodID
    None, 		# CallStaticObjectMethod
    None, 		# CallStaticObjectMethodV
    None, 		# CallStaticObjectMethodA
    None, 		# CallStaticBooleanMethod
    None, 		# CallStaticBooleanMethodV
    None, 		# CallStaticBooleanMethodA
    None, 		# CallStaticByteMethod
    None, 		# CallStaticByteMethodV
    None, 		# CallStaticByteMethodA
    None, 		# CallStaticCharMethod
    None, 		# CallStaticCharMethodV
    None, 		# CallStaticCharMethodA
    None, 		# CallStaticShortMethod
    None, 		# CallStaticShortMethodV
    None, 		# CallStaticShortMethodA
    None, 		# CallStaticIntMethod
    None, 		# CallStaticIntMethodV
    None, 		# CallStaticIntMethodA
    None, 		# CallStaticLongMethod
    None, 		# CallStaticLongMethodV
    None, 		# CallStaticLongMethodA
    None, 		# CallStaticFloatMethod
    None, 		# CallStaticFloatMethodV
    None, 		# CallStaticFloatMethodA
    None, 		# CallStaticDoubleMethod
    None, 		# CallStaticDoubleMethodV
    None, 		# CallStaticDoubleMethodA
    None, 		# CallStaticVoidMethod
    None, 		# CallStaticVoidMethodV
    None, 		# CallStaticVoidMethodA
    None, 		# GetStaticFieldID
    None, 		# GetStaticObjectField
    None, 		# GetStaticBooleanField
    None, 		# GetStaticByteField
    None, 		# GetStaticCharField
    None, 		# GetStaticShortField
    None, 		# GetStaticIntField
    None, 		# GetStaticLongField
    None, 		# GetStaticFloatField
    None, 		# GetStaticDoubleField
    None, 		# SetStaticObjectField
    None, 		# SetStaticBooleanField
    None, 		# SetStaticByteField
    None, 		# SetStaticCharField
    None, 		# SetStaticShortField
    None, 		# SetStaticIntField
    None, 		# SetStaticLongField
    None, 		# SetStaticFloatField
    None, 		# SetStaticDoubleField
    None, 		# NewString
    None, 		# GetStringLength
    None, 		# GetStringChars
    None, 		# ReleaseStringChars
    None, 		# NewStringUTF
    None, 		# GetStringUTFLength
    None, 		# GetStringUTFChars
    None, 		# ReleaseStringUTFChars
    "GetArrayLength", # GetArrayLength
    None, 		# NewObjectArray
    None, 		# GetObjectArrayElement
    None, 		# SetObjectArrayElement
    "NewBooleanArray", # NewBooleanArray
    "NewByteArray", # NewByteArray
    "NewCharArray", # NewCharArray
    "NewShortArray", # NewShortArray
    "NewIntArray", # NewIntArray
    "NewLongArray", # NewLongArray
    None, 		# NewFloatArray
    None, 		# NewDoubleArray
    "GetArrayElements", # GetBooleanArrayElements
    "GetArrayElements", # GetByteArrayElements
    "GetArrayElements", # GetCharArrayElements
    "GetArrayElements", # GetShortArrayElements
    "GetArrayElements", # GetIntArrayElements
    "GetArrayElements", # GetLongArrayElements
    None, 		# GetFloatArrayElements
    None, 		# GetDoubleArrayElements
    None, 		# ReleaseBooleanArrayElements
    "ReleaseArrayElements", # ReleaseByteArrayElements
    "ReleaseArrayElements", # ReleaseCharArrayElements
    "ReleaseArrayElements", # ReleaseShortArrayElements
    "ReleaseArrayElements", # ReleaseIntArrayElements
    "ReleaseArrayElements", # ReleaseLongArrayElements
    None, 		# ReleaseFloatArrayElements
    None, 		# ReleaseDoubleArrayElements
    "GetArrayRegion", # GetBooleanArrayRegion
    "GetArrayRegion", # GetByteArrayRegion
    "GetArrayRegion", # GetCharArrayRegion
    "GetArrayRegion", # GetShortArrayRegion
    "GetArrayRegion", # GetIntArrayRegion
    "GetArrayRegion", # GetLongArrayRegion
    None, 		# GetFloatArrayRegion
    None, 		# GetDoubleArrayRegion
    "SetArrayRegion", # SetBooleanArrayRegion
    "SetArrayRegion", # SetByteArrayRegion
    "SetArrayRegion", # SetCharArrayRegion
    "SetArrayRegion", # SetShortArrayRegion
    "SetArrayRegion", # SetIntArrayRegion
    "SetArrayRegion", # SetLongArrayRegion
    None, 		# SetFloatArrayRegion
    None, 		# SetDoubleArrayRegion
    None, 		# RegisterNatives
    None, 		# UnregisterNatives
    None, 		# MonitorEnter
    None, 		# MonitorExit
    None, 		# GetJavaVM
    None, 		# GetStringRegion
    None, 		# GetStringUTFRegion
    "GetArrayElements", # GetPrimitiveArrayCritical
    "ReleaseArrayElements", # ReleasePrimitiveArrayCritical
    None, 		# GetStringCritical
    None, 		# ReleaseStringCritical
    None, 		# NewWeakGlobalRef
    None, 		# DeleteWeakGlobalRef
    None, 		# ExceptionCheck
    None, 		# NewDirectByteBuffer
    None, 		# GetDirectBufferAddress
    None, 		# GetDirectBufferCapacity
    None, 		# GetObjectRefType
]
