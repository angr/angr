
from .plugin import KnowledgeBasePlugin
from ..misc.ux import deprecated


class LabelsPlugin(KnowledgeBasePlugin):
    """Storage for program labels. Access with kb.labels.    
    
    A label "name" is a label named "name", duh. Labels can be grouped into the seperate namespaces.
    An address is allowed to have a different labels within different namespace, but it is not allowed
    for address to have a different labels within a single namespace.
    
    The default namespace is set to empty string.
    """

    _default_ns_name = ''

    def __init__(self, kb, copy=False):
        super(KnowledgeBasePlugin, self).__init__()

        self._namespaces = {}
        self._default_ns = self._default_ns_name
        self.add_namespace(self._default_ns_name)

        if not copy:
            # TODO: This should be done in LabelsImport analysis. Here for compat reasons only.
            for obj in kb._project.loader.all_objects:
                for k, v in obj.symbols_by_addr.iteritems():
                    if v.name and not v.is_import:
                        self.set_label(v.rebased_addr, v.name)
                try:
                    for k, v in obj.plt.iteritems():
                        self.set_label(v, k)
                except AttributeError:
                    pass

    def copy(self):
        o = LabelsPlugin(None, copy=True)
        o._namespaces = {k: v.copy() for k, v in self._namespaces.iteritems()}
        o._default_ns = self._default_ns
        return o

    #
    #   ...
    #

    def __getattr__(self, name):
        try:
            super(LabelsPlugin, self).__getattribute__(name)
        except AttributeError:
            namespace = self._namespaces[self.default_namespace]
            return getattr(namespace, name)

    def __iter__(self):
        namespace = self._namespaces[self.default_namespace]
        return iter(namespace)

    def __getitem__(self, addr):
        namespace = self._namespaces[self.default_namespace]
        return namespace[addr]

    def __delitem__(self, addr):
        namespace = self._namespaces[self.default_namespace]
        del namespace[addr]

    def __contains__(self, addr):
        namespace = self._namespaces[self.default_namespace]
        return addr in namespace

    #
    #   ...
    #

    @deprecated(replacement='get_label')
    def get(self, addr):
        namespace = self._namespaces[self.default_namespace]
        return namespace.get_name(addr)

    @deprecated(replacement='get_addr')
    def lookup(self, name):
        namespace = self._namespaces[self.default_namespace]
        addr = namespace.get_addr(name)
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
        if self._default_ns not in self._namespaces:
            self.add_namespace(self._default_ns)

    def get_namespace(self, name=None):
        """
        
        :param name: 
        :return: 
        """
        if name is None:
            name = self.default_namespace
        return self._namespaces[name]

    def add_namespace(self, name):
        if name in self._namespaces:
            raise ValueError("Namespace %r already exists" % name)
        self._namespaces[name] = LabelsNamespace(name)


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

    def __getitem__(self, addr):
        name = self.get_name(addr)
        if name is None:
            raise KeyError(addr)
        return name

    def __setitem__(self, addr, name):
        self.set_label(addr, name)

    def __delitem__(self, addr):
        self.del_addr(addr)

    def __contains__(self, addr):
        return self.has_addr(addr)

    def __iter__(self):
        return iter(self._name_to_addr)

    def copy(self):
        o = LabelsNamespace(self._name)
        o._name_to_addr = self._name_to_addr.copy()
        o._addr_to_names = self._addr_to_names.copy()
        return o

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

    def has_name(self, name):
        """
        
        :param name: 
        :return: 
        """
        return name in self._name_to_addr

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

    def has_addr(self, addr):
        """
        
        :param addr: 
        :return: 
        """
        return addr in self._addr_to_names

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
