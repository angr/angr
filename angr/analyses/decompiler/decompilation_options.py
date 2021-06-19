# decompilation options

from collections import defaultdict


class DecompilationOption:
    def __init__(self, name, description, value_type, cls, param, value_range=None, category="General",
                 default_value=None, clears_cache=True):
        self.name = name
        self.description = description
        self.value_type = value_type
        self.cls = cls
        self.param = param
        self.value_range = value_range
        self.category = category
        self.default_value = default_value
        self.clears_cache = clears_cache


O = DecompilationOption

options = [
    O(
        "Aggressively remove dead memdefs",
        "Allow the decompiler to aggressively remove memory definitions (such as stack variables) that are deemed dead."
        " Generally, enabling this option will generate cleaner pseudocode; However, due to limitations of static "
        "analysis, angr may miss certain uses to a memory definition, which may cause the removal of a memory "
        "definition that is actually in use, and consequently lead to incorrect decompilation output.",
        bool,
        "clinic",
        "remove_dead_memdefs",
        category="Data flows",
        default_value=False,
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
    ),
    O(
        "Show casts",
        "Disabling this option will blindly remove all C typecast constructs from pseudocode output.",
        bool,
        "codegen",
        "show_casts",
        category="Display",
        default_value=True,
        clears_cache=False,
    ),
    O(
        "Braces on own lines",
        "Highly controversial. Disable this to see \"} else {\".",
        bool,
        "codegen",
        "braces_on_own_lines",
        category="Display",
        default_value=True,
        clears_cache=False,
    )
]

options_by_category = defaultdict(list)

for o in options:
    options_by_category[o.category].append(o)
