from . import JNISimProcedure
from ...engines.soot.values.constants import SimSootValue_ClassConstant

import logging
l = logging.getLogger('angr.procedures.java_jni.getsuperclass')

class GetSuperclass(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, class_):
        class_name = self.state.jni_references.lookup(class_).class_name
        if class_name == "java.lang.Object":
            return 0
        superclass_name = self.state.javavm_classloader.get_superclass(class_name).name
        if superclass_name:
            superclass = SimSootValue_ClassConstant.from_classname(superclass_name)
            return self.state.jni_references.create_new_reference(superclass)
        else:
            l.error("Couldn't identify superclass of %s" % class_name)
            return 0