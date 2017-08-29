from collections import defaultdict, Iterable

from bidict import bidict

from .plugin import KnowledgeBasePlugin
from ..misc.ux import deprecated


class LabelsPlugin(KnowledgeBasePlugin):
    """Storage for program labels. Access with kb.labels.    
    
    A label "name" is a label named "name", duh. Labels can be grouped into the seperate namespaces.
    An address is allowed to have a different labels within different namespace, but it is not allowed
    for address to have a different labels within a single namespace.
    
    The global namespace defaults to empty string.
       
    :var _global_ns:    The name of the global namespace.
    :type _global_ns:   str
    """

    _global_ns = ''

    def __init__(self, kb, copy=False):
        super(KnowledgeBasePlugin, self).__init__()
        self._namespaces = defaultdict(bidict)

        if not copy:
            # TODO: This should be done somewhere else. Here for compat reasons only.
            for obj in kb._project.loader.all_objects:
                for k, v in obj.symbols_by_addr.iteritems():
                    if v.name:
                        # Original logic implies overwriting existing labels.
                        if self.get_addr(v.name):
                            self.del_label(v.name)
                        self.set_label(v.rebased_addr, v.name)
                try:
                    for k, v in obj.plt.iteritems():
                        # Original logic implies overwriting existing labels.
                        if self.get_addr(k):
                            self.del_label(k)
                        self.set_label(v, k)
                except AttributeError:
                    pass

    def copy(self):
        o = LabelsPlugin(None, copy=True)
        o._namespaces = self._namespaces.copy()
        return o

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
        if self.get_addr(k) is not None:
            self.del_label(k)
        elif self.get_label(v) is not None:
            self.del_addr(v)
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

        # Name is already present in the namespace.
        # Here we forbid assigning different addresses with the same name.
        if name in namespace and namespace[name] != addr:
            raise ValueError("Label '%s' is already in present in the namespace "
                             "'%s' with an address %#x, different from %#x"
                             % (name, ns, namespace[name], addr))

        # Specified address is already labeled.
        # Here we forbid assigning different labels to a single address.
        if addr in namespace.inv and namespace.inv[addr] != name:
            raise ValueError("Address %#x is already labeled with '%s' "
                             "in the namespace '%s'" % (addr, name, ns))

        # Create a new label!
        namespace[name] = addr

    def get_label(self, addr, ns=_global_ns, default=None):
        """Get a label that is present within the given namespace and is assigned to the specified address.
        
        :param addr:    The address for which the label is assigned.
        :param ns:      The namespace to look into.
        :param default: The name of the label to assign to the address, if there is no label present.
                        This accepts the following values: 
                            True - assign a new label with default name; 
                            None - don't do anything, i.e. return None if the address is not labeled; 
                            Any other value - create a new label with the given value.
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
        """Delete a label that is present within the given namespace.
        
        :param name:    The name of the label which is to be deleted.
        :param ns:      The namespace in which the given label is present.
        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        if name not in namespace:
            raise ValueError("Namespace '%s' doesn't have a label named '%s'" % (ns, name))

        del namespace[name]

    def iter_labels(self, addr, ns_set=None):
        """Iterate over labels that are assigned to a given address in the given set of namespaces.
        
        :param addr:    An address for which to yield assigned labels.
        :param ns_set:  A set of namespaces to work with.
        :return:        Tuples of (namespace, label).
        """
        ns_set = self._normalize_ns_set(ns_set)

        for ns in ns_set:
            yield ns, self.get_label(addr, ns)

    #
    #   ...
    #

    def get_addr(self, name, ns=_global_ns, default=None):
        """Get the address for the label in the given namespace.
        
        :param name:    The label name.
        :param ns:      The namespace to look into.
        :param default: Default value if the label is not present in the given namespace.
        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        return namespace.get(name, default)

    def del_addr(self, addr, ns=_global_ns):
        """Delete a label that is assigned to the given address within the given namespace.

        :param addr:    The address from which to remove a label in the given namespace.
        :param ns:      The namespace in which the given address is present.
        :return: 
        """
        namespace = self._namespaces[ns]  # a shorthand

        if addr not in namespace.inv:
            raise ValueError("Namespace '%s' doesn't have a label on address %#x" % (ns, addr))

        del namespace.inv[addr]

    def iter_addrs(self, name, ns_set=None):
        """Iterate over address that have a label with a given name in the given set of namespaces. 
        
        :param name:    The name of the labels.
        :param ns_set:  A set of namespaces to work with.
        :return:        Tuples of (namespace, addr).
        """
        ns_set = self._normalize_ns_set(ns_set)

        for ns in ns_set:
            yield ns, self.get_addr(name, ns)

    #
    #   ...
    #

    def _generate_default_label(self, addr):
        """Generate a default label for the given address.
        
        :param addr:    The address to generate a label for.
        :return:        A default label for the given address.
        """
        return 'lbl_%x' % addr

    def _normalize_ns_set(self, thing):
        if thing is None:
            return set(self._namespaces)
        elif isinstance(thing, Iterable):
            return set(thing)
        else:
            raise TypeError("ns_set must be an instance of Iterable")


KnowledgeBasePlugin.register_default('labels', LabelsPlugin)
