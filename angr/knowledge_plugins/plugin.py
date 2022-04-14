default_plugins = {}


class KnowledgeBasePlugin:

    def copy(self):
        raise NotImplementedError

    @staticmethod
    def register_default(name, cls):
        if name in default_plugins:
            raise Exception("%s is already set as the default for %s" % (default_plugins[name], name))
        default_plugins[name] = cls
