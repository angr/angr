import logging

from archinfo.arch_soot import ArchSoot, SootFieldDescriptor

from . import JNISimProcedure
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
        return self._get_field_id(field_class, field_name, field_type)

    def _get_field_id(self, field_class, field_name, field_type):

        # Background:
        # In Java, fields are not polymorphic and the class declaring the field
        # is determined statically by the declaring variable.
        # Also fields are uniquely defined by the tuple (field_name, field_type)
        # and in particular *not* by its attributes (e.g. 'STATIC').
        # => This both together implies that we do not have to distinguish between
        #    static and instance fields.

        # fields can be defined in superclasses (and TODO: superinterfaces)
        # => walk up in class hierarchy
        class_hierarchy = self.state.javavm_classloader.get_class_hierarchy(field_class)
        for class_ in class_hierarchy:
            # check for every class, if it contains the field
            if self._class_contains_field(class_, field_name, field_type):
                self.state.javavm_classloader.init_class(class_)
                # if so, create the field_id and return a reference to it
                field_id = SootFieldDescriptor(class_.name, field_name, field_type)
                return self.state.jni_references.create_new_reference(field_id)

        # field couldn't be found
        # => return null and (TODO:) throw an NoSuchFieldError
        l.debug("Couldn't find field %s in classes %s.", class_hierarchy, field_name)
        return 0

    @staticmethod
    def _class_contains_field(field_class, field_name, field_type):
        # check if field is loaded in CLE
        if not field_class.is_loaded:
            return False
        # check if a field with the given name exists
        if not field_name in field_class.fields:
            return False
        field = field_class.fields[field_name]
        # check type
        if field[1] != field_type:
            return False
        return True

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
        value = self.state.project.simos.cast_primitive(value=value_.to_claripy(),
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
        value = self.state.project.simos.cast_primitive(value=value_.to_claripy(),
                                                        to_type=field_id.type)
        # store value in java memory
        self.state.javavm_memory.store(field_ref, value)
