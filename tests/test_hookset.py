# pylint: disable=missing-class-docstring,disable=no-self-use
import unittest

import angr


class TestHookSet(unittest.TestCase):
    def test_hookset(self):
        class Foo:
            def run(self):
                return self.blah()

            def blah(self):  # pylint:disable=no-self-use
                return ["foo"]

            def install_hooks(self, tech):
                angr.misc.HookSet.install_hooks(self, blah=tech.blah)

            def remove_hooks(self, tech):
                angr.misc.HookSet.remove_hooks(self, blah=tech.blah)

        class Bar:
            def blah(self, foo):  # pylint:disable=no-self-use
                return ["bar"] + foo.blah()

        class Baz:
            def blah(self, foo):  # pylint:disable=no-self-use
                return ["baz"] + foo.blah()

        class Coward:
            def blah(self, foo):  # pylint:disable=no-self-use,unused-argument
                return ["coward"]

        foo = Foo()
        assert foo.run() == ["foo"]

        bar = Bar()
        baz = Baz()
        foo.install_hooks(bar)
        foo.install_hooks(baz)
        assert foo.run() == ["baz", "bar", "foo"]

        foo.remove_hooks(bar)
        foo.remove_hooks(baz)
        assert foo.run() == ["foo"]

        coward = Coward()
        foo.install_hooks(coward)
        assert foo.run() == ["coward"]

        foo.remove_hooks(coward)
        assert foo.run() == ["foo"]


if __name__ == "__main__":
    unittest.main()
