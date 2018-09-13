import logging

from ..java import JavaSimProcedure

l = logging.getLogger('angr.procedures.java.class.getSimpleName')


class GetSimpleName(JavaSimProcedure):

    __provides__ = (
        ("java.lang.Class", "getSimpleName()"),
    )

    def run(self, class_descriptor): # pylint: disable=arguments-differ
        class_name = class_descriptor.name
        return class_name.split('.')[-1]
