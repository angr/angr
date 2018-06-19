from .base import SimSootValue

class SimSootValue_StringRef(SimSootValue):

    __slots__ = [ 'id', 'type', 'heap_alloc_id' ]

    def __init__(self, heap_alloc_id):
        self.heap_alloc_id = heap_alloc_id
        self.type = "java.lang.String"
        self.id = self._create_unique_id(self.heap_alloc_id, self.type)


    @staticmethod
    def _create_unique_id(heap_alloc_id, class_name):
        return "%s.%s.value" % (heap_alloc_id, class_name)

    def __repr__(self):
        return self.id