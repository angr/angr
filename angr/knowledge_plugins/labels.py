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
    :var _default_ns:   The default namespace to use for operating. Defaults to _global_ns.
    :type _default_ns:  str
    """

    _global_ns = ''

    def __init__(self, kb, copy=False):
        super(KnowledgeBasePlugin, self).__init__()
        self._namespaces = defaultdict(bidict)
        self._default_ns = self._global_ns

        if not copy:
            # TODO: This should be done somewhere else. Here for compat reasons only.
            for obj in kb._project.loader.all_objects:
                for k, v in obj.symbols_by_addr.iteritems():
                    if v.name:
                        # Original logic implies overwriting existing labels.
                        if self.get_addr(v.name):
                            self.del_name(v.name)
                        self.set_label(v.rebased_addr, v.name)
                try:
                    for k, v in obj.plt.iteritems():
                        # Original logic implies overwriting existing labels.
                        if self.get_addr(k):
                            self.del_name(k)
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
            self.del_name(k)
        elif self.get_name(v) is not None:
            self.del_addr(v)
        self.set_label(v, k)

    def __delitem__(self, k):
        self.del_name(k)

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

    @property
    def default_namespace(self):
        return self._default_ns

    @default_namespace.setter
    def default_namespace(self, name):
        self._default_ns = name

    #
    #   ...
    #

    def set_label(self, addr, name, ns=None):
        """Label address `addr` as `name` within namespace `namespace`
        
        :param addr:        The address to put a label on.
        :param name:        The name of the label.
        :param ns:          The namespace to register label to.

        :return: 
        """
        namespace = self._get_namespace_dict(ns)

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

    #
    #   ...
    #

    def get_name(self, addr, ns=None, default=None):
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
        namespace = self._get_namespace_dict(ns)

        if addr not in namespace.inv and default:
            if default is True:
                default = self._generate_default_label(addr)
            return namespace.setdefault(default, addr)

        else:
            return namespace.inv.get(addr)

    def del_name(self, name, ns=None):
        """Delete a label that is present within the given namespace.
        
        :param name:    The name of the label which is to be deleted.
        :param ns:      The namespace in which the given label is present.
        :return: 
        """
        namespace = self._get_namespace_dict(ns)

        if name not in namespace:
            raise ValueError("Namespace '%s' doesn't have a label named '%s'" % (ns, name))

        del namespace[name]

    def iter_names(self, addr, ns_set=None):
        """Iterate over labels that are assigned to a given address in the given set of namespaces.
        
        :param addr:    An address for which to yield assigned labels.
        :param ns_set:  A set of namespaces to work with.
        :return:        Tuples of (namespace, label).
        """
        ns_set = self._normalize_ns_set(ns_set)

        for ns in ns_set:
            yield ns, self.get_name(addr, ns)

    #
    #   ...
    #

    def get_addr(self, name, ns=None, default=None):
        """Get the address for the label in the given namespace.
        
        :param name:    The label name.
        :param ns:      The namespace to look into.
        :param default: Default value if the label is not present in the given namespace.
        :return: 
        """
        namespace = self._get_namespace_dict(ns)

        return namespace.get(name, default)

    def del_addr(self, addr, ns=None):
        """Delete a label that is assigned to the given address within the given namespace.

        :param addr:    The address from which to remove a label in the given namespace.
        :param ns:      The namespace in which the given address is present.
        :return: 
        """
        namespace = self._get_namespace_dict(ns)

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

    def _get_namespace_dict(self, ns=None):
        if ns is None:
            ns = self._default_ns
        return self._namespaces[ns]

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


class LabelsNamespace(object):
    """
    This represents a single labels namespace. The addresses to names relations are represented
    with a one-to-many mapping. That means every address can have multiple names, but every name is
    assigned to only one address.
    
    :ivar _name_to_addr:    A mapping from name to its assigned address.
    :type _name_to_addr:    dict
    :ivar _addr_to_names:   A mapping from address to a list of assigned names. The first name
                            in a list will be the default name for the address.
    :type _addr_to_names:   dict of lists
    """

    def __init__(self, name):
        self._name = name  # here for better repr only
        self._name_to_addr = {}
        self._addr_to_names = {}

    def __str__(self):
        return "<LabelsNamespace(%s)>" % repr(self._name)

    def __repr__(self):
        return str(self)

    #
    #   ...
    #

    def set_label(self, addr, name, make_default=False):
        """Assign a name to a given address.

        :param addr:            An address to be assigned with a name.
        :param name:            A name to be assigned to address.
        :param make_default:    True, if the given name should be the default name for the address.
        :return: 
        """
        if self._name_to_addr.get(name, addr) != addr:
            raise ValueError("Name %s is already assigned to address %#x" %
                             (name, self._name_to_addr[name]))

        self._name_to_addr[name] = addr
        names_list = self._addr_to_names.setdefault(addr, [])

        if make_default is True:
            names_list.insert(0, name)
        else:
            names_list.append(name)

    #
    #   ...
    #

    def get_name(self, addr, default=None):
        """
        
        :param addr: 
        :param default: 
        :return: 
        """
        return self._addr_to_names.get(addr, [default])[0]

    def get_all_names(self, addr):
        """
        
        :param addr: 
        :return: 
        """
        return self._addr_to_names.get(addr, [])

    def del_name(self, name):
        """
        
        :param name: 
        :return: 
        """
        if name not in self._name_to_addr:
            raise KeyError("No such name: %s" % name)

        addr = self._name_to_addr.pop(name)
        self._addr_to_names[addr].remove(name)

    def iter_names(self):
        """
        
        :return: 
        """
        return iter(self._name_to_addr)

    #
    #   ...
    #

    def get_addr(self, name, default=None):
        """
        
        :param name: 
        :param default: 
        :return: 
        """
        return self._name_to_addr.get(name, default)

    def del_addr(self, addr):
        """
        
        :param addr: 
        :return: 
        """
        if addr not in self._addr_to_names:
            raise KeyError("No such address: %#x" % addr)

        names_list = self._addr_to_names.pop(addr)
        map(self._name_to_addr.pop, names_list)

    def iter_addrs(self):
        """
        
        :return: 
        """
        return iter(self._addr_to_names)

    #
    #   ...
    #

    def iter_labels(self):
        return self._name_to_addr.iteritems()


KnowledgeBasePlugin.register_default('labels', LabelsPlugin)
