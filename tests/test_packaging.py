"""Tier A: what the distribution claims about itself, checked against the tree.

Nothing here touches a node or an event loop. It exists because three of the
files that ship with the wheel are prose or metadata rather than code, and prose
that has drifted from the code fails nowhere:

- `[project.scripts]` puts an executable on a user's PATH. One naming a module
  that does not exist is a `ModuleNotFoundError` at the shell, discoverable only
  after installing.
- `readme = "README.md"` makes that file the PyPI long description -- the first
  and often the only thing a caller reads. It documented the synchronous SDK that
  commit `e580b03` deleted, in full: `with astral.connect(...) as node`,
  `node.whoami()`, `from astral import obj, eos, ack, blob`, `ws://` and `http://`
  endpoints, and "Requires Python 3.8+" against `requires-python = ">=3.11"`.
  None of it existed.
- `astral.__all__` is the facade. A name in it that is not importable is a
  promise the package does not keep.

So the assertions are mechanical: every module the metadata names imports, every
name the README shows exists, and the version floor the README states is the one
`pyproject.toml` declares.
"""

from __future__ import annotations

import importlib
import pathlib
import re
import tomllib
import unittest

import astral

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"


def metadata() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


class ConsoleScriptTest(unittest.TestCase):
    def test_every_console_script_names_a_module_that_imports(self):
        """`astral-query = "astral.cli:main"` shipped in the wheel's
        entry_points.txt while `src/astral/cli.py` did not exist, so installing
        the distribution put an executable on PATH that fails with
        `ModuleNotFoundError: No module named 'astral.cli'`."""
        scripts = metadata().get("project", {}).get("scripts", {})
        for name, target in scripts.items():
            with self.subTest(script=name):
                module, _, attr = target.partition(":")
                imported = importlib.import_module(module)
                self.assertTrue(
                    hasattr(imported, attr),
                    f"{name} points at {target}, which has no {attr!r}",
                )


class FacadeTest(unittest.TestCase):
    def test_every_name_in_all_is_importable(self):
        for name in astral.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(astral, name))

    def test_the_exception_hierarchy_is_complete_and_rooted(self):
        """`except astral.AstralError` is the documented catch-all, so every
        exception the facade exports has to be under it."""
        from astral import errors

        for name in errors.__all__:
            obj = getattr(errors, name)
            if isinstance(obj, type) and issubclass(obj, BaseException):
                with self.subTest(name=name):
                    self.assertTrue(issubclass(obj, astral.AstralError))
                    self.assertIn(name, astral.__all__)


class ReadmeTest(unittest.TestCase):
    """The long description, checked rather than trusted."""

    def setUp(self) -> None:
        self.text = README.read_text(encoding="utf-8")

    def test_the_python_floor_matches_the_metadata(self):
        floor = metadata()["project"]["requires-python"]
        self.assertIn("3.11", floor)
        self.assertIn("Python 3.11", self.text)
        self.assertNotIn("Python 3.8", self.text)

    def test_the_readme_shows_no_name_the_package_does_not_export(self):
        """`from astral import obj, eos, ack, blob, AstralObject` was the
        headline example and every one of those names is gone."""
        for statement in re.findall(r"^from astral import (.+)$", self.text, re.M):
            for name in (part.strip() for part in statement.split(",")):
                with self.subTest(name=name):
                    self.assertTrue(hasattr(astral, name))

    def test_every_client_attribute_the_readme_uses_exists(self):
        """`node.identity`, `node.alias`, `node.whoami()`, `node.tree`,
        `node.crypto` -- five attributes `Client` has never had."""
        from astral.client import Client

        used = set(re.findall(r"\bclient\.([a-z_]+)", self.text))
        for name in sorted(used):
            with self.subTest(attribute=name):
                self.assertTrue(
                    hasattr(Client, name), f"README uses client.{name}, which is absent"
                )

    def test_the_readme_does_not_advertise_a_synchronous_facade(self):
        """`connect()` is a coroutine function and `Client` has no `__enter__`,
        so `with astral.connect(...) as node:` -- the old quick start -- raises."""
        import inspect

        self.assertTrue(inspect.iscoroutinefunction(astral.connect))
        self.assertFalse(hasattr(astral.Client, "__enter__"))
        self.assertNotIn("with astral.connect(", self.text)

    def test_the_readme_claims_no_transport_that_raises(self):
        """`ws://` and `http://` raise `TransportUnsupported` until step 14, so
        the README may name them as pending and never as usable endpoints."""
        for line in self.text.splitlines():
            if line.lstrip().startswith(("astral.connect(", "await astral.connect(")):
                with self.subTest(line=line):
                    self.assertNotIn("ws://", line)
                    self.assertNotIn("http://", line)


if __name__ == "__main__":
    unittest.main()
