from . import JNISimProcedure
from ...engines.soot.values import SimSootValue_ThisRef
from .method_calls import CallMethodBase

# pylint: disable=arguments-differ,unused-argument

#
# GetObjectClass
#


class GetObjectClass(JNISimProcedure):
    return_ty = "reference"

    def run(self, ptr_env, obj_):
        obj = self.state.jni_references.lookup(obj_)
        obj_class = self.state.javavm_classloader.get_class(obj.type)
        return self.state.jni_references.create_new_reference(obj_class)


#
# AllocObject
#


class AllocObject(JNISimProcedure):
    return_ty = "reference"

    def run(self, ptr_env, obj_class_):
        obj_class = self.state.jni_references.lookup(obj_class_)
        # make sure class is initialized
        self.state.javavm_classloader.init_class(obj_class)
        # return object reference
        obj = SimSootValue_ThisRef(heap_alloc_id=self.state.javavm_memory.get_new_uuid(), type_=obj_class.name)
        return self.state.jni_references.create_new_reference(obj)


#
# NewObject
#


class NewObject(CallMethodBase):
    return_ty = "reference"
    obj = None
    local_vars = ("obj",)

    def run(self, ptr_env, obj_class_, method_id_):
        # alloc object
        obj_class = self.state.jni_references.lookup(obj_class_)
        self.state.javavm_classloader.init_class(obj_class)
        self.obj = SimSootValue_ThisRef(heap_alloc_id=self.state.javavm_memory.get_new_uuid(), type_=obj_class.name)
        # call constructor
        method_id = self.state.jni_references.lookup(method_id_)
        self._invoke(method_id, self.obj, dynamic_dispatch=False)

    def return_from_invocation(self, ptr_env, obj_class_, method_id_):
        return self.state.jni_references.create_new_reference(self.obj)


#
# IsInstanceOf
#


class IsInstanceOf(CallMethodBase):
    return_ty = "boolean"

    def run(self, ptr_env, obj_, target_class_):
        target_class = self.state.jni_references.lookup(target_class_)
        obj = self.state.jni_references.lookup(obj_)
        obj_class = self.state.javavm_classloader.get_class(obj.type)
        # check if target class equals either the object class or one of its superclasses
        class_hierarchy = self.state.javavm_classloader.get_class_hierarchy(obj_class)
        if target_class in class_hierarchy:
            return self.JNI_TRUE
        else:
            return self.JNI_FALSE


#
# IsSameObject
#


class IsSameObject(JNISimProcedure):
    return_ty = "boolean"

    def run(self, ptr_env, ref1_, ref2_):
        ref1 = self.state.jni_references.lookup(ref1_)
        ref2 = self.state.jni_references.lookup(ref2_)
        if ref1 == ref2:
            return self.JNI_TRUE
        else:
            return self.JNI_FALSE
