from collections import defaultdict, Iterable

from bidict import bidict

from .plugin import KnowledgeBasePlugin
from ..misc.ux import deprecated


class LabelsPlugin(KnowledgeBasePlugin):
    """Storage for program labels. Access with kb.labels.    
    
    A label "name" is a label named "name", duh. Labels can be grouped into the seperate namespaces.
    An address is allowed to have a different labels within different namespace, but it is not allowed
    for address to have a different labels within a single namespace.
    
    The global namespace is the empty string.
       
    :var _global_ns:    The name of the global namespace.
    :type _global_ns:   str
    """

    _global_ns = ''

    def __init__(self, kb):
        super(KnowledgeBasePlugin, self).__init__()
        self._namespaces = defaultdict(bidict)

        # # TODO: This should be done somewhere else. Here for compat reasons only.
        # for obj in kb._project.loader.all_objects:
        #     for k, v in obj.symbols_by_addr.iteritems():
        #         if v.name:
        #             self.set_label(v.rebased_addr, v.name)
        #     if hasattr(obj, 'plt'):
        #         for v, k in obj.plt.iteritems():
        #             self.set_label(v, k)

    #
    #   ...
    #

    # NOTE: The following works only with global namespace for comptaibility reasons.

    @property
    def _global_namespace(self):
        return self._namespaces[self._global_ns]

    def __iter__(self):
        return iter(self._global_namespace)

    def __getitem__(self, k):
        return self._global_namespace[k]

    def __setitem__(self, k, v):
        self.set_label(v, k)

    def __delitem__(self, k):
        self.del_label(k)

    def __contains__(self, k):
        return k in self._global_namespace

    #
    #   ...
    #

    @deprecated(replacement='get_label')
    def get(self, addr):
        return self[addr]

    @deprecated(replacement='get_addr')
    def lookup(self, name):
        addr = self.get_addr(name)
        if addr is None:
            raise KeyError(name)
        return addr

    #
    #   ...
    #

    def set_label(self, addr, name, ns=_global_ns):
        """Label address `addr` as `name` within namespace `namespace`
        
        :param addr:        The address to put a label on.
        :param name:        The name of the label.
        :param ns:          The namespace to register label to.

        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        if name in namespace:
            # Name is already present in the namespace.
            # Here we forbid to assigning different addresses with the same name.
            if namespace.inv[name] != addr:
                raise ValueError("Label '%s' is already in present in the namespace "
                                 "'%s' with a different address %#x" % (name, ns, addr))

        elif addr not in namespace.inv:
            # Create a new label!
            namespace[name] = addr

        else:
            raise ValueError("Address %#x is already labeled with '%s' "
                             "in the namespace '%s'" % (addr, name, ns))

    def get_label(self, addr, ns=_global_ns, default=None):
        """Get a label that is present within the given namespace and is assigned to the specified address.
        
        :param addr: 
        :param ns: 
        :param default:
        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        if addr not in namespace.inv and default:
            if default is True:
                default = self._generate_default_label(addr)
            return namespace.setdefault(default, addr)

        else:
            return namespace.inv.get(addr)

    def del_label(self, name, ns=_global_ns):
        """Delete a label that is present within the given namespace and is assigned to the specified address.
        
        :param name: 
        :param ns: 
        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        if name not in namespace:
            raise ValueError("Namespace '%s' doesn't have a label named '%s'" % (ns, name))

        del namespace[name]

    def iter_labels(self, addr, ns_set=None):
        """
        
        :param addr: 
        :param ns_set: 
        :return: 
        """
        if ns_set is None:
            ns_set = set(self._namespaces)
        elif isinstance(ns_set, Iterable):
            ns_set = set(ns_set)
        else:
            raise TypeError("ns_set must be an Iterable")

        for ns in ns_set:
            yield ns, self.get_label(addr, ns)

    #
    #   ...
    #

    def get_addr(self, name, ns=_global_ns, default=None):
        """
        
        :param name: 
        :param ns: 
        :param default: 
        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        return namespace.get(name, default)

    #
    #   ...
    #

    def _generate_default_label(self, addr):
        return 'lbl_%#x' % addr


KnowledgeBasePlugin.register_default('labels', LabelsPlugin)
