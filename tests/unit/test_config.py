"""Standard-library unittest coverage for the dependency-free config surface.

The existing suite under tests/ is written for pytest. This module mirrors a
subset of that coverage using only the standard library so the catalog,
the explicit-deny list, and Settings can be exercised in an environment with no
third-party packages installed at all -- the same "no install required" promise
the README makes for the offline path. It imports and runs the real
``sift_sentinel.config`` module; nothing here is mocked.

Run with:  python3 -m unittest discover -s tests/unit
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

# Make the src/ layout importable without an editable install, so this runs
# under a bare `python3 -m unittest discover -s tests/unit`.
_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sift_sentinel import config  # noqa: E402
from sift_sentinel.config import (  # noqa: E402
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_MODEL,
    DENIED_TOOLS,
    READONLY_TOOLS,
    Settings,
)


class CatalogTests(unittest.TestCase):
    def test_readonly_catalog_is_non_empty_and_described(self) -> None:
        self.assertGreater(len(READONLY_TOOLS), 0)
        for name, description in READONLY_TOOLS.items():
            self.assertTrue(name, "tool name must be a non-empty string")
            self.assertTrue(
                description.strip(),
                f"tool '{name}' must carry a human-readable description",
            )

    def test_denied_catalog_is_non_empty_and_described(self) -> None:
        self.assertGreater(len(DENIED_TOOLS), 0)
        for name, reason in DENIED_TOOLS.items():
            self.assertTrue(name)
            self.assertTrue(reason.strip(), f"denied tool '{name}' must state a reason")

    def test_allowlist_and_denylist_are_disjoint(self) -> None:
        # A tool that is both allowlisted and explicitly denied would make the
        # guardrail's ordering load-bearing in a surprising way; keep them apart.
        overlap = set(READONLY_TOOLS) & set(DENIED_TOOLS)
        self.assertEqual(overlap, set(), f"tools in both lists: {sorted(overlap)}")

    def test_destructive_classics_are_denied(self) -> None:
        # The README's threat model calls these out by name.
        for destructive in ("dd", "mkfs", "rm"):
            self.assertIn(destructive, DENIED_TOOLS)

    def test_integrity_tools_are_allowlisted(self) -> None:
        # sha256sum anchors chain of custody; it must be runnable.
        self.assertIn("sha256sum", READONLY_TOOLS)


class SettingsTests(unittest.TestCase):
    def test_defaults_match_module_constants(self) -> None:
        settings = Settings()
        self.assertEqual(settings.model, DEFAULT_MODEL)
        self.assertEqual(settings.max_iterations, DEFAULT_MAX_ITERATIONS)
        self.assertEqual(settings.allowlist, frozenset(READONLY_TOOLS))

    def test_settings_is_frozen(self) -> None:
        settings = Settings()
        with self.assertRaises(Exception):
            settings.model = "something-else"  # type: ignore[misc]

    def test_allowlist_defaults_are_independent_instances(self) -> None:
        # field(default_factory=...) means two Settings must not share state.
        a = Settings()
        b = Settings()
        self.assertEqual(a.allowlist, b.allowlist)
        self.assertIsNot(a.allowlist, b.allowlist)

    def test_from_env_reads_overrides(self) -> None:
        preserved = {
            key: os.environ.get(key)
            for key in (
                "SIFT_SENTINEL_MODEL",
                "SIFT_SENTINEL_MAX_ITERATIONS",
                "SIFT_SENTINEL_MCP_COMMAND",
                "ANTHROPIC_API_KEY",
            )
        }
        try:
            os.environ["SIFT_SENTINEL_MODEL"] = "claude-test-model"
            os.environ["SIFT_SENTINEL_MAX_ITERATIONS"] = "7"
            os.environ["SIFT_SENTINEL_MCP_COMMAND"] = "fake-mcp"
            os.environ["ANTHROPIC_API_KEY"] = "sk-ant-fake"
            settings = Settings.from_env()
            self.assertEqual(settings.model, "claude-test-model")
            self.assertEqual(settings.max_iterations, 7)
            self.assertEqual(settings.mcp_command, "fake-mcp")
            self.assertEqual(settings.api_key, "sk-ant-fake")
            self.assertEqual(settings.allowlist, frozenset(READONLY_TOOLS))
        finally:
            for key, value in preserved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_from_env_falls_back_to_defaults(self) -> None:
        preserved = {
            key: os.environ.pop(key, None)
            for key in (
                "SIFT_SENTINEL_MODEL",
                "SIFT_SENTINEL_MAX_ITERATIONS",
                "SIFT_SENTINEL_MCP_COMMAND",
                "ANTHROPIC_API_KEY",
            )
        }
        try:
            settings = Settings.from_env()
            self.assertEqual(settings.model, DEFAULT_MODEL)
            self.assertEqual(settings.max_iterations, DEFAULT_MAX_ITERATIONS)
            self.assertIsNone(settings.api_key)
        finally:
            for key, value in preserved.items():
                if value is not None:
                    os.environ[key] = value


class OptionalDotenvTests(unittest.TestCase):
    def test_load_dotenv_is_always_callable(self) -> None:
        # Whether python-dotenv is installed or not, config exposes a callable
        # load_dotenv so importing the package never hard-fails on the dep.
        self.assertTrue(callable(config.load_dotenv))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
