import logging

from archinfo.arch_soot import ArchSoot

from . import JNISimProcedure
from ...engines.soot.exceptions import SootFieldNotLoadedException
from ...engines.soot.field_dispatcher import resolve_field
from ...engines.soot.values import (SimSootValue_InstanceFieldRef,
                                    SimSootValue_StaticFieldRef)

l = logging.getLogger('angr.procedures.java_jni.field_access')

# pylint: disable=arguments-differ,unused-argument

#
# GetFieldID / GetStaticFieldID
#

class GetFieldID(JNISimProcedure):

    return_ty = "reference"

    def run(self, ptr_env, field_class_, ptr_field_name, ptr_field_sig):
        field_class = self.state.jni_references.lookup(field_class_)
        field_name = self._load_string_from_native_memory(ptr_field_name)
        field_sig = self._load_string_from_native_memory(ptr_field_sig)
        # get type from type signature
        field_type = ArchSoot.decode_type_signature(field_sig)
        # resolve field
        try:
            field_id = resolve_field(self.state, field_class, field_name, field_type,
                                     raise_exception_if_not_found=True)
            return self.state.jni_references.create_new_reference(field_id)
        except SootFieldNotLoadedException:
            # field could not be found
            # => return null and (TODO:) throw an NoSuchFieldError
            return 0

#
# GetStatic<Type>Field
#

class GetStaticField(JNISimProcedure):

    return_ty = None

    def run(self, ptr_env, _, field_id_):
        # get field reference
        field_id = self.state.jni_references.lookup(field_id_)
        field_ref = SimSootValue_StaticFieldRef(class_name=field_id.class_name,
                                                field_name=field_id.name,
                                                type_=field_id.type)
        # load value from java memory
        return self.state.javavm_memory.load(field_ref, none_if_missing=True)

class GetStaticBooleanField(GetStaticField):
    return_ty = 'boolean'
class GetStaticByteField(GetStaticField):
    return_ty = 'byte'
class GetStaticCharField(GetStaticField):
    return_ty = 'char'
class GetStaticShortField(GetStaticField):
    return_ty = 'short'
class GetStaticIntField(GetStaticField):
    return_ty = 'int'
class GetStaticLongField(GetStaticField):
    return_ty = 'long'
class GetStaticObjectField(GetStaticField):
    return_ty = 'reference'

#
# SetStaticField
#

class SetStaticField(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, field_class_, field_id_, value_):
        field_class = self.state.jni_references.lookup(field_class_)
        field_id = self.state.jni_references.lookup(field_id_)
        # get field reference
        field_ref = SimSootValue_StaticFieldRef(class_name=field_class.name,
                                                field_name=field_id.name,
                                                type_=field_id.type)
        # cast value to java type
        value = self.state.project.simos.cast_primitive(state=self.state,
                                                        value=value_.to_claripy(),
                                                        to_type=field_id.type)
        # store value in java memory
        self.state.javavm_memory.store(field_ref, value)

#
# Get<Type>Field
#

class GetField(JNISimProcedure):

    return_ty = None

    def run(self, ptr_env, obj_, field_id_):
        # get field reference
        obj = self.state.jni_references.lookup(obj_)
        field_id = self.state.jni_references.lookup(field_id_)
        field_ref = SimSootValue_InstanceFieldRef(heap_alloc_id=obj.heap_alloc_id,
                                                  class_name=field_id.class_name,
                                                  field_name=field_id.name,
                                                  type_=field_id.type)
        # load value from java memory
        return self.state.javavm_memory.load(field_ref, none_if_missing=True)

class GetBooleanField(GetField):
    return_ty = 'boolean'
class GetByteField(GetField):
    return_ty = 'byte'
class GetCharField(GetField):
    return_ty = 'char'
class GetShortField(GetField):
    return_ty = 'short'
class GetIntField(GetField):
    return_ty = 'int'
class GetLongField(GetField):
    return_ty = 'long'
class GetObjectField(GetField):
    return_ty = 'reference'

#
# Set<Type>Field
#

class SetField(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, obj_, field_id_, value_):
        obj = self.state.jni_references.lookup(obj_)
        field_id = self.state.jni_references.lookup(field_id_)
        # get field reference
        field_ref = SimSootValue_InstanceFieldRef(heap_alloc_id=obj.heap_alloc_id,
                                                  class_name=field_id.class_name,
                                                  field_name=field_id.name,
                                                  type_=field_id.type)
        # cast value to java type
        value = self.state.project.simos.cast_primitive(state=self.state,
                                                        value=value_.to_claripy(),
                                                        to_type=field_id.type)
        # store value in java memory
        self.state.javavm_memory.store(field_ref, value)
