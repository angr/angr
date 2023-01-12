default_plugins = {}


class KnowledgeBasePlugin:
    def copy(self):
        raise NotImplementedError

    @staticmethod
    def register_default(name, cls):
        if name in default_plugins:
            raise Exception(f"{default_plugins[name]} is already set as the default for {name}")
        default_plugins[name] = cls
