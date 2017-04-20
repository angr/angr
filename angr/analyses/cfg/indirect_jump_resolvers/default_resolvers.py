
import cle

from . import MipsElfFastResolver
from . import X86ElfPicPltResolver


DEFAULT_RESOLVERS = {
    'X86': {
        cle.MetaELF: [ X86ElfPicPltResolver, ],
    },
    'MIPS32': {
        cle.MetaELF: [ MipsElfFastResolver, ],
    }
}


def default_indirect_jump_resolvers(arch, obj, project=None):
    arch_specific = DEFAULT_RESOLVERS.get(arch.name, { })
    resolvers = [ ]
    for k, lst in arch_specific.iteritems():
        if isinstance(obj, k):
            resolvers = lst
            break

    return [ r(project) for r in resolvers ]
