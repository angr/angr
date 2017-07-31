
import cle

from . import MipsElfFastResolver
from . import X86ElfPicPltResolver
from . import JumpTableResolver


DEFAULT_RESOLVERS = {
    'X86': {
        cle.MetaELF: [ X86ElfPicPltResolver, ],
    },
    'MIPS32': {
        cle.MetaELF: [ MipsElfFastResolver, ],
    },
    'ALL': [ JumpTableResolver ],
}


def default_indirect_jump_resolvers(arch, obj, project=None):
    arch_specific = DEFAULT_RESOLVERS.get(arch.name, { })
    resolvers = [ ]
    for k, lst in arch_specific.iteritems():
        if isinstance(obj, k):
            resolvers = lst
            break

    resolvers += DEFAULT_RESOLVERS['ALL']

    return [ r(arch=project.arch, project=project) for r in resolvers ]
