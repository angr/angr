from . import JNISimProcedure

from archinfo.arch_soot import ArchSoot, SootAddressDescriptor
from ...calling_conventions import SimCCSoot
from ...engines.soot.values import SimSootValue_Local

import logging
l = logging.getLogger('angr.procedures.java_jni.callmethod')

class CallMethodBase(JNISimProcedure):

    return_ty = None

    def _call_java_method(self, this_ref, method_id, arg_values):
        
        # Step 1: invoke addr
        invoke_addr = SootAddressDescriptor(method_id, 0, 0)

        # Step 2: setup arguments
        args = []

        # this reference
        args = [(this_ref, this_ref.type)]

        # function arguments
        for arg_value_, arg_type in zip(arg_values, method_id.params):

            if arg_type in ['float', 'double']:
                # argument has a primitive floating-point type
                raise NotImplementedError('No support for floating-point arguments.')

            elif arg_type in ArchSoot.primitive_types:
                # argument has a primitive integral type
                # => cast native value to java type
                arg_value = self.project.simos.cast_primitive(value=arg_value_, to_type=arg_type)

            else:
                # argument has a relative type
                # => lookup java object
                arg_value = self.state.jni_references.lookup(arg_value_)
            
            args += [(arg_value, arg_type)]
        
        # Step 3: call java method
        # => after the method return, the execution will be continued in _return_result_of_computation
        self.call(invoke_addr, args, "_return_result_of_computation", cc=SimCCSoot(ArchSoot()))


    def _return_result_of_computation(self, ptr_env, obj_, method_id_, _):
        if self.return_ty != 'void':
            ret_value = self.state.get_javavm_view_of_plugin('registers').load('invoke_return_value')
            if self.return_ty == 'reference':
                return self.state.jni_references.create_new_reference(ret_value)
            else:
                return ret_value

#
# Call<Type>Method
#

class CallMethod(CallMethodBase):
    
    def run(self, ptr_env, obj_, method_id_):
        method_id = self.state.jni_references.lookup(method_id_)
        this_ref = self.state.jni_references.lookup(obj_)
        arg_values = [ self.arg(self.num_args+idx).to_claripy() 
                       for idx in range(len(method_id.params)) ]
        self._call_java_method(this_ref, method_id, arg_values)


class CallObjectMethod(CallMethod):
    return_ty = 'reference'

class CallBooleanMethod(CallMethod):
    return_ty = 'boolean'

class CallByteMethod(CallMethod):
    return_ty = 'byte'

class CallCharMethod(CallMethod):
    return_ty = 'char'

class CallShortMethod(CallMethod):
    return_ty = 'short'

class CallIntMethod(CallMethod):
    return_ty = 'int'

class CallLongMethod(CallMethod):
    return_ty = 'long'

class CallVoidMethod(CallMethod):
    return_ty = 'void'

#
# Call<Type>MethodA
#

class CallMethodA(CallMethodBase):

    def run(self, ptr_env, obj_, method_id_, ptr_args):
        method_id = self.state.jni_references.lookup(method_id_)
        this_ref = self.state.jni_references.lookup(obj_)
        arg_values = self.load_from_native_memory(addr=ptr_args,
                                                  value_size=self.arch.bytes, 
                                                  no_of_elements=len(method_id.params))
        self._call_java_method(this_ref, method_id, arg_values)

class CallObjectMethodA(CallMethodA):
    return_ty = 'reference'

class CallBooleanMethodA(CallMethodA):
    return_ty = 'boolean'

class CallByteMethodA(CallMethodA):
    return_ty = 'byte'

class CallCharMethodA(CallMethodA):
    return_ty = 'char'

class CallShortMethodA(CallMethodA):
    return_ty = 'short'

class CallIntMethodA(CallMethodA):
    return_ty = 'int'

class CallLongMethodA(CallMethodA):
    return_ty = 'long'

class CallVoidMethodA(CallMethodA):
    return_ty = 'void'
