# pylint:disable=import-outside-toplevel
import os.path
import sys
import importlib.util
from importlib.machinery import ModuleSpec


class FastPkgResources():

    def __getattribute__(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            # fallback to the real pkg_resources
            remove_fake_pkg_resources()
            import pkg_resources
            return getattr(pkg_resources, name)

    def __spec__(self):
        return ModuleSpec("pkg_resources", None)

    def resource_filename(self, package, resource_name):
        r = self._resource_filename(package, resource_name)
        if r is None:
            # fallback to the real pkg_resources
            remove_fake_pkg_resources()
            import pkg_resources
            return pkg_resources.resource_filename(package, resource_name)
        return r

    def _resource_filename(self, package, resource_name):
        spec = importlib.util.find_spec(package)
        if spec is None:
            return None
        if not spec.origin:
            return None
        if os.path.isfile(spec.origin):
            # get the directory
            base_dir = os.path.dirname(spec.origin)
        else:
            base_dir = spec.origin
        resource_path = os.path.join(base_dir, resource_name)
        if os.path.exists(resource_path):
            return resource_path
        return None


def import_fake_pkg_resources(force=False):
    if force or 'pkg_resources' not in sys.modules:
        sys.modules['pkg_resources'] = FastPkgResources()


def remove_fake_pkg_resources():
    if isinstance(sys.modules.get('pkg_resources', None), FastPkgResources):
        sys.modules.pop('pkg_resources')
