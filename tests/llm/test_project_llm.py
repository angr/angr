# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.llm"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.llm_client import LLMClient

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestProjectLLMClient(unittest.TestCase):
    """Tests for LLM client integration with angr.Project."""

    def _get_project(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        return angr.Project(bin_path, auto_load_libs=False)

    def test_llm_client_default_none(self):
        """Project.llm_client should be None when no env vars are set."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANGR_LLM_")}
        with mock.patch.dict(os.environ, env, clear=True):
            proj = self._get_project()
            assert proj.llm_client is None

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_llm_client_lazy_init_from_env(self):
        """Project.llm_client should be lazy-initialized from env vars."""
        env = {
            "ANGR_LLM_MODEL": "test-model",
            "ANGR_LLM_API_KEY": "test-key",
        }
        with mock.patch.dict(os.environ, env):
            proj = self._get_project()
            client = proj.llm_client
            assert client is not None
            assert client.model == "test-model"
            assert client.api_key == "test-key"

    def test_llm_client_cached_after_first_access(self):
        """Project.llm_client should return the same object on subsequent accesses."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANGR_LLM_")}
        with mock.patch.dict(os.environ, env, clear=True):
            proj = self._get_project()
            first = proj.llm_client
            second = proj.llm_client
            assert first is second  # same None, but importantly not re-checked

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_llm_client_setter(self):
        """Project.llm_client can be set manually."""
        proj = self._get_project()
        client = LLMClient(model="manual-model")
        proj.llm_client = client
        assert proj.llm_client is client
        assert proj.llm_client.model == "manual-model"

    @mock.patch.dict("sys.modules", {"litellm": mock.MagicMock()})
    def test_llm_client_setter_override_env(self):
        """Manually set llm_client takes precedence over env vars."""
        env = {"ANGR_LLM_MODEL": "env-model"}
        with mock.patch.dict(os.environ, env):
            proj = self._get_project()
            manual_client = LLMClient(model="manual-model")
            proj.llm_client = manual_client
            assert proj.llm_client.model == "manual-model"

    def test_llm_client_set_to_none(self):
        """Project.llm_client can be explicitly set to None."""
        proj = self._get_project()
        proj.llm_client = None
        assert proj.llm_client is None

    def test_llm_client_excluded_from_pickle(self):
        """_llm_client should not appear in pickled state."""
        proj = self._get_project()
        state = proj.__getstate__()
        assert "_llm_client" not in state

    def test_llm_client_reset_after_unpickle(self):
        """After unpickling, llm_client should be lazy-initialized again."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANGR_LLM_")}
        with mock.patch.dict(os.environ, env, clear=True):
            proj = self._get_project()
            # Simulate pickle round-trip via getstate/setstate
            state = proj.__getstate__()
            proj2 = object.__new__(angr.Project)
            proj2.__setstate__(state)
            # After setstate, accessing llm_client should re-check env (and find None)
            assert proj2.llm_client is None


if __name__ == "__main__":
    unittest.main()
