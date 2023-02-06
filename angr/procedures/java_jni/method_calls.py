import logging
from typing import Optional

from archinfo.arch_soot import ArchSoot, SootAddressDescriptor, SootArgument, SootMethodDescriptor

from . import JNISimProcedure
from ...calling_conventions import SimCCSoot
from ...engines.soot.method_dispatcher import resolve_method

l = logging.getLogger("angr.procedures.java_jni.callmethod")

# pylint: disable=arguments-differ,unused-argument

#
# GetMethodID / GetStaticMethodID
#


class GetMethodID(JNISimProcedure):
    return_ty = "reference"

    def run(self, ptr_env, class_, ptr_method_name, ptr_method_sig):
        method_class = self.state.jni_references.lookup(class_)
        method_name = self._load_string_from_native_memory(ptr_method_name)
        method_sig = self._load_string_from_native_memory(ptr_method_sig)

        # derive parameter type from signature
        params, _ = ArchSoot.decode_method_signature(method_sig)

        # create method ID and return reference to it
        method_id = SootMethodDescriptor(method_class.name, method_name, params)
        return self.state.jni_references.create_new_reference(method_id)


#
# Call<Type>Method / CallNonvirtual<Type>Method / CallStatic<Type>Method
#


class CallMethodBase(JNISimProcedure):
    return_ty: Optional[str] = None

    def _invoke(self, method_id, obj=None, dynamic_dispatch=True, args_in_array=None):
        # get invoke target
        class_name = obj.type if dynamic_dispatch else method_id.class_name
        invoke_target = resolve_method(self.state, method_id.name, class_name, method_id.params)
        invoke_addr = SootAddressDescriptor(invoke_target, 0, 0)

        # get args
        no_of_args = len(invoke_target.params)
        if args_in_array is not None:
            arg_values = self._get_arg_values_from_array(args_in_array, no_of_args)
        else:
            arg_values = self._get_arg_values(no_of_args)

        # setup java args
        java_args = self._setup_java_args(arg_values, invoke_target, this_ref=obj)

        # call java method
        # => after returning, the execution will be continued in _return_result_of_computation
        self.call(invoke_addr, java_args, "return_from_invocation", cc=SimCCSoot(ArchSoot()))

    def _get_arg_values(self, no_of_args):
        return [self.va_arg("void*") for _ in range(no_of_args)]

    def _get_arg_values_from_array(self, array, no_of_args):
        return self._load_from_native_memory(
            addr=array, data_size=self.arch.bytes, no_of_elements=no_of_args, return_as_list=True
        )

    def _setup_java_args(self, arg_values, method_id, this_ref=None):
        args = []

        # if available, add 'this' reference
        if this_ref:
            args += [SootArgument(this_ref, this_ref.type, is_this_ref=True)]

        # function arguments
        for arg_value_, arg_type in zip(arg_values, method_id.params):
            if arg_type in ArchSoot.primitive_types:
                # argument has a primitive integral type
                # => cast native value to java type
                arg_value = self.project.simos.cast_primitive(self.state, value=arg_value_, to_type=arg_type)

            else:
                # argument has a relative type
                # => lookup java object
                arg_value = self.state.jni_references.lookup(arg_value_)

            args += [SootArgument(arg_value, arg_type)]

        return args

    def _return_from_invocation(self):
        if self.return_ty != "void":
            ret_value = self.state.javavm_registers.load("invoke_return_value")
            if self.return_ty == "reference":
                return self.state.jni_references.create_new_reference(ret_value)
            else:
                return ret_value


#
# Call<Type>Method
#


class CallMethod(CallMethodBase):
    def run(self, ptr_env, obj_, method_id_):
        method_id = self.state.jni_references.lookup(method_id_)
        obj = self.state.jni_references.lookup(obj_)
        self._invoke(method_id, obj, dynamic_dispatch=True)

    def return_from_invocation(self, ptr_env, obj_, method_id_):
        return self._return_from_invocation()


class CallMethodA(CallMethodBase):
    def run(self, ptr_env, obj_, method_id_, ptr_args):
        method_id = self.state.jni_references.lookup(method_id_)
        obj = self.state.jni_references.lookup(obj_)
        self._invoke(method_id, obj, dynamic_dispatch=True, args_in_array=ptr_args)

    def return_from_invocation(self, ptr_env, obj_, method_id_, ptr_args):
        return self._return_from_invocation()


class CallObjectMethod(CallMethod):
    return_ty = "reference"


class CallBooleanMethod(CallMethod):
    return_ty = "boolean"


class CallByteMethod(CallMethod):
    return_ty = "byte"


class CallCharMethod(CallMethod):
    return_ty = "char"


class CallShortMethod(CallMethod):
    return_ty = "short"


class CallIntMethod(CallMethod):
    return_ty = "int"


class CallLongMethod(CallMethod):
    return_ty = "long"


class CallVoidMethod(CallMethod):
    return_ty = "void"


class CallObjectMethodA(CallMethodA):
    return_ty = "reference"


class CallBooleanMethodA(CallMethodA):
    return_ty = "boolean"


class CallByteMethodA(CallMethodA):
    return_ty = "byte"


class CallCharMethodA(CallMethodA):
    return_ty = "char"


class CallShortMethodA(CallMethodA):
    return_ty = "short"


class CallIntMethodA(CallMethodA):
    return_ty = "int"


class CallLongMethodA(CallMethodA):
    return_ty = "long"


class CallVoidMethodA(CallMethodA):
    return_ty = "void"


#
# CallNonVirtual<Type>Method
#


class CallNonvirtualMethod(CallMethodBase):
    def run(self, ptr_env, obj_, class_, method_id_):
        method_id = self.state.jni_references.lookup(method_id_)
        obj = self.state.jni_references.lookup(obj_)
        self._invoke(method_id, obj, dynamic_dispatch=False)

    def return_from_invocation(self, ptr_env, obj_, class_, method_id_):
        return self._return_from_invocation()


class CallNonvirtualMethodA(CallMethodBase):
    def run(self, ptr_env, obj_, method_id_, ptr_args):
        method_id = self.state.jni_references.lookup(method_id_)
        obj = self.state.jni_references.lookup(obj_)
        self._invoke(method_id, obj, dynamic_dispatch=False, args_in_array=ptr_args)

    def return_from_invocation(self, ptr_env, obj_, method_id_, ptr_args):
        return self._return_from_invocation()


class CallNonvirtualObjectMethod(CallNonvirtualMethod):
    return_ty = "reference"


class CallNonvirtualBooleanMethod(CallNonvirtualMethod):
    return_ty = "boolean"


class CallNonvirtualByteMethod(CallNonvirtualMethod):
    return_ty = "byte"


class CallNonvirtualCharMethod(CallNonvirtualMethod):
    return_ty = "char"


class CallNonvirtualShortMethod(CallNonvirtualMethod):
    return_ty = "short"


class CallNonvirtualIntMethod(CallNonvirtualMethod):
    return_ty = "int"


class CallNonvirtualLongMethod(CallNonvirtualMethod):
    return_ty = "long"


class CallNonvirtualVoidMethod(CallNonvirtualMethod):
    return_ty = "void"


class CallNonvirtualObjectMethodA(CallNonvirtualMethodA):
    return_ty = "reference"


class CallNonvirtualBooleanMethodA(CallNonvirtualMethodA):
    return_ty = "boolean"


class CallNonvirtualByteMethodA(CallNonvirtualMethodA):
    return_ty = "byte"


class CallNonvirtualCharMethodA(CallNonvirtualMethodA):
    return_ty = "char"


class CallNonvirtualShortMethodA(CallNonvirtualMethodA):
    return_ty = "short"


class CallNonvirtualIntMethodA(CallNonvirtualMethodA):
    return_ty = "int"


class CallNonvirtualLongMethodA(CallNonvirtualMethodA):
    return_ty = "long"


class CallNonvirtualVoidMethodA(CallNonvirtualMethodA):
    return_ty = "void"


#
# CallStatic<Type>Method
#


class CallStaticMethod(CallMethodBase):
    def run(self, ptr_env, class_, method_id_):
        method_id = self.state.jni_references.lookup(method_id_)
        self._invoke(method_id, dynamic_dispatch=False)

    def return_from_invocation(self, ptr_env, class_, method_id_):
        return self._return_from_invocation()


class CallStaticMethodA(CallMethodBase):
    def run(self, ptr_env, obj_, method_id_, ptr_args):
        method_id = self.state.jni_references.lookup(method_id_)
        self._invoke(method_id, dynamic_dispatch=False, args_in_array=ptr_args)

    def return_from_invocation(self, ptr_env, class_, method_id_, ptr_args):
        return self._return_from_invocation()


class CallStaticObjectMethod(CallStaticMethod):
    return_ty = "reference"


class CallStaticBooleanMethod(CallStaticMethod):
    return_ty = "boolean"


class CallStaticByteMethod(CallStaticMethod):
    return_ty = "byte"


class CallStaticCharMethod(CallStaticMethod):
    return_ty = "char"


class CallStaticShortMethod(CallStaticMethod):
    return_ty = "short"


class CallStaticIntMethod(CallStaticMethod):
    return_ty = "int"


class CallStaticLongMethod(CallStaticMethod):
    return_ty = "long"


class CallStaticVoidMethod(CallStaticMethod):
    return_ty = "void"


class CallStaticObjectMethodA(CallStaticMethodA):
    return_ty = "reference"


class CallStaticBooleanMethodA(CallStaticMethodA):
    return_ty = "boolean"


class CallStaticByteMethodA(CallStaticMethodA):
    return_ty = "byte"


class CallStaticCharMethodA(CallStaticMethodA):
    return_ty = "char"


class CallStaticShortMethodA(CallStaticMethodA):
    return_ty = "short"


class CallStaticIntMethodA(CallStaticMethodA):
    return_ty = "int"


class CallStaticLongMethodA(CallStaticMethodA):
    return_ty = "long"


class CallStaticVoidMethodA(CallStaticMethodA):
    return_ty = "void"
