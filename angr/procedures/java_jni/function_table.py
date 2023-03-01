import collections
import typing

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
