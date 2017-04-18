
from . import MipsElfFastResolver


DEFAULT_RESOLVERS = {
    'MIPS32': [ MipsElfFastResolver, ]
}


def default_indirect_jump_resolvers(arch_name):
    arch_specific = DEFAULT_RESOLVERS.get(arch_name, [ ])

    resolvers = arch_specific

    return [ r() for r in resolvers ]
