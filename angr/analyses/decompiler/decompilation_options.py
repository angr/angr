# decompilation options
from typing import Optional, List, Callable
from collections import defaultdict

from .structuring import structurer_class_from_name
from .structuring.phoenix import MultiStmtExprMode


class DecompilationOption:
    """
    Describes a decompilation option.
    """

    def __init__(
        self,
        name,
        description,
        value_type,
        cls,
        param,
        value_range=None,
        category="General",
        default_value=None,
        clears_cache=True,
        candidate_values: Optional[List] = None,
        convert: Optional[Callable] = None,
    ):
        self.NAME = name
        self.DESCRIPTION = description
        self.value_type = value_type
        self.cls = cls
        self.param = param
        self.value_range = value_range
        self.category = category
        self.default_value = default_value
        self.clears_cache = clears_cache
        self.candidate_values = candidate_values
        self.convert = convert

    def __repr__(self):
        return f"<DecOption [{self.category}] {self.NAME} ({self.cls}.{self.param})>"


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
        "Rewrite ITE expressions into diamond-shaped control-flow regions",
        "Rewrite ITE expressions into diamond-shaped control-flow regions, which usually result in better decompilation"
        " output.",
        bool,
        "clinic",
        "rewrite_ites_to_diamonds",
        category="Graph",
        default_value=True,
    ),
    O(
        "Leave the largest loop successor tree outside the loop region",
        "During region identification, treating the largest successor tree of a loop as a member of the loop body "
        "sometimes leads to seemingly unnatural and gigantic loops. Enabling this option will treat such successor "
        "trees not as a member of the loop body.",
        bool,
        "region_identifier",
        "largest_successor_tree_outside_loop",
        category="Graph",
        default_value=True,
    ),
    O(
        "Simplify switches by undoing switch clustering",
        "Undoing switch clustering that modern compilers employ. Switch clustering will split a switch into "
        "multiple pieces and transform (or lower) them piece-by-piece for better performance (and lower readability).",
        bool,
        "region_simplifier",
        "simplify_switches",
        category="Graph",
        default_value=True,
    ),
    O(
        "Simplify if-else to remove terminating else scopes",
        "Removes terminating else scopes to make the code appear more flat.",
        bool,
        "region_simplifier",
        "simplify_ifelse",
        category="Graph",
        default_value=True,
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
        "Comment gotos",
        "Disabling this option will uncomment gotos currently shown in output.",
        bool,
        "codegen",
        "comment_gotos",
        category="Display",
        default_value=False,
        clears_cache=False,
    ),
    O(
        "Braces on own lines",
        'Highly controversial. Disable this to see "} else {".',
        bool,
        "codegen",
        "braces_on_own_lines",
        category="Display",
        default_value=True,
        clears_cache=False,
    ),
    O(
        "Use compound assignment operators",
        'Reduce statements "a = a + b" to "a += b".',
        bool,
        "codegen",
        "use_compound_assignments",
        category="Display",
        default_value=True,
        clears_cache=False,
    ),
    O(
        "Show local types",
        "When decompilation generates typedefs, show them before the function body",
        bool,
        "codegen",
        "show_local_types",
        category="Display",
        default_value=True,
        clears_cache=False,
    ),
    O(
        "Show externs",
        "Declare global variables used in this function with the `extern` keyword.",
        bool,
        "codegen",
        "show_externs",
        category="Display",
        default_value=True,
        clears_cache=False,
    ),
    O(
        "Show demangled name",
        "Demangles names in higher-level languages like C++",
        bool,
        "codegen",
        "show_demangled_name",
        category="Display",
        default_value=True,
        clears_cache=True,
    ),
    O(
        "Show disambiguated names",
        "Disambiguate function names when they conflict with variables and other functions",
        bool,
        "codegen",
        "show_disambiguated_name",
        category="Display",
        default_value=True,
        clears_cache=True,
    ),
    O(
        "Structuring algorithm",
        "Select a structuring algorithm. Currently supports Dream and Phoenix.",
        type,
        "recursive_structurer",
        "structurer_cls",
        category="Structuring",
        default_value="Phoenix",
        candidate_values=["Dream", "Phoenix"],
        clears_cache=True,
        convert=structurer_class_from_name,
    ),
    O(
        "Improve structuring algorithm",
        "If applicable in deeper structurer, like Phoenix, improves decompilation output",
        bool,
        "recursive_structurer",
        "improve_structurer",
        category="Structuring",
        default_value=True,
        clears_cache=True,
    ),
    O(
        "C-style null compares",
        "Rewrites the (x == 0) => (!x) && (x != 0) => (x)",
        bool,
        "codegen",
        "cstyle_null_cmp",
        category="Display",
        default_value=True,
        clears_cache=True,
    ),
    O(
        "Simplified else",
        "Removes redundant else scopes",
        bool,
        "codegen",
        "simplify_else_scope",
        category="Display",
        default_value=True,
        clears_cache=True,
    ),
    O(
        "C-style if statements",
        "Omits braces for single statement if blocks that have no else",
        bool,
        "codegen",
        "cstyle_ifs",
        category="Display",
        default_value=True,
        clears_cache=True,
    ),
    O(
        "Multi-expression statements generation",
        "Should the structuring algorithm generate multi-expression statements? If so, under what conditions?",
        type,
        "recursive_structurer",
        "use_multistmtexprs",
        category="Structuring",
        default_value=MultiStmtExprMode.MAX_ONE_CALL.value,
        candidate_values=[op.value for op in MultiStmtExprMode],
        clears_cache=True,
        convert=MultiStmtExprMode,
    ),
]

# NOTE: if you add a codegen option here, please add it to reapply_options

options_by_category = defaultdict(list)
PARAM_TO_OPTION = {}

for o in options:
    options_by_category[o.category].append(o)
    PARAM_TO_OPTION[o.param] = o


#
# Option Helpers
#


def get_structurer_option() -> Optional[DecompilationOption]:
    for opt in options:
        if opt.cls == "recursive_structurer" and opt.param == "structurer_cls":
            return opt
    return None
