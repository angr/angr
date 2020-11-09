# decompilation options

from collections import defaultdict


class DecompilationOption:
    def __init__(self, name, description, value_type, cls, param, value_range=None, category="General",
                 default_value=None):
        self.name = name
        self.description = description
        self.value_type = value_type
        self.cls = cls
        self.param = param
        self.value_range = value_range
        self.category = category
        self.default_value = default_value


O = DecompilationOption

options = [
    O(
        "Remove dead memdefs",
        "Allow the decompiler to remove memory definitions (such as stack variables) that are deemed dead. Generally, "
        "enabling this option will generate cleaner pseudocode; But when prior analyses go wrong, angr may miss "
        "certain uses to a memory definition, which may cause the removal of a memory definition that is in use.",
        bool,
        "clinic",
        "remove_dead_memdefs",
        category="Data flows",
        default_value=True,
    ),
    O(
        "Display exception edges (experimental)",
        "Decompile and display exception handling code. Enabling this option generally degrades the readability of the "
        "pseudo code. This is still an experimental feature.",
        bool,
        "clinic",
        "exception_edges",
        category="Graph",
        default_value=False,
    )
]

options_by_category = defaultdict(list)

for o in options:
    options_by_category[o.category].append(o)
