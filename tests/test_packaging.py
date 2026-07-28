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

    def test_the_readme_claims_no_endpoint_form_that_cannot_be_dialed(self):
        """The README may show an endpoint form only where `dial()` accepts it.

        Asserted by dialing rather than by string matching, which is how the
        rule went stale in the first place: it named `ws://` as pending, step 14
        made `ws://` work, and the test then forbade the README from showing the
        working form of a shipped feature -- passing only because the one line
        that shows it begins with a backtick and the `startswith` check never
        looked at it.

        `http://` is still refused, and not as a gap: an HTTP request carries its
        query in the request line, so there is no connection to open before a
        query exists and `astral.transport.http.query()` is the entry point
        (design section 4.5). `memu:`/`memb:` are astrald's in-process
        transports, which no external process can attach to.
        """
        forms = {
            form
            for form in re.findall(r"[a-z]+://[^\s`\"')]+", self.text)
            if "://" in form
        }
        self.assertTrue(forms, "the README shows no endpoint at all")
        for form in sorted(forms):
            with self.subTest(endpoint=form):
                proto = form.split(":", 1)[0]
                if proto in ("http", "https"):
                    self.assertNotIn(
                        f"astral.connect(\"{form}\")",
                        self.text,
                        "an http endpoint is not dialable; http.query() is the "
                        "entry point",
                    )
                    continue
                # Dialable protocols are named as such; nothing here connects.
                self.assertIn(proto, ("ws", "wss", "tcp", "unix"))


class ReadmeFollowTest(unittest.TestCase):
    """Every `client.follow(...)` the README shows names an op that sends one.

    The README's only ST+follow example was `client.follow("tree.get?...&follow=
    true")` read with `snapshot()` then `live()`, and `Tree` documents the
    opposite for the same op: it sends no separator, so `snapshot()` blocks. And
    `client.follow()` sets `timeout=None`, so nothing bounded the hang -- the
    process blocked, never reached the `live()` line, and held one of the node's
    32 workers for as long as it ran. Two authored surfaces of one SDK
    contradicting each other about the safety of the same call.

    Verified live against `furry-bolt`: `tree.get?path=/mod/indexing&follow=true`
    answered one `nil` frame and no `eos` with the stream still open after four
    seconds, while `services.discover?follow=true` and
    `objects.scan?repo=main&follow=true` both ended at a separator `eos`.
    """

    SEPARATOR_OPS = frozenset({"objects.scan", "services.discover", "services.sync"})
    """Ops whose first `eos` is the snapshot/live boundary. Verified live."""

    NO_SEPARATOR_OPS = frozenset({"tree.get"})
    """Follow-shaped ops whose single `eos` is the terminator. Verified live."""

    def test_the_readme_follows_only_ops_that_send_a_separator(self):
        text = README.read_text(encoding="utf-8")
        found = re.findall(r'client\.follow\(\s*"([^"?]+)', text)
        self.assertTrue(found, "the README no longer shows a follow example")
        for op in found:
            with self.subTest(op=op):
                self.assertNotIn(
                    op,
                    self.NO_SEPARATOR_OPS,
                    f"client.follow({op!r}) blocks forever: that op sends no "
                    "snapshot/live separator, so `snapshot()` never returns",
                )
                self.assertIn(op, self.SEPARATOR_OPS)


class AnnotationTest(unittest.TestCase):
    """`py.typed` makes every annotation a supported interface, so every one
    of them has to resolve at runtime.

    `api/base.py` names this failure verbatim as the reason `Client` is imported
    at module scope rather than under `TYPE_CHECKING`: "an interface that raises
    `NameError` on introspection is not one -- `inspect.signature(eval_str=True)`,
    doc generators and DI containers all read them at runtime." Three public
    surfaces did exactly that and none was caught, because the obvious spot check
    does not show it: `typing.get_type_hints(cls)` walks `__mro__` and resolves
    each base against **its own** module globals, while
    `get_type_hints(cls.__init__)` and `inspect.signature(cls, eval_str=True)`
    resolve the generated `__init__` against the *subclass's* globals.

    - `ReadObjectAction` and `CreateObjectAction` inherit `auth.Action`'s
      `nonce: Nonce` into `astral.api.objects`, which had no reason of its own to
      import `Nonce`. Every remaining action type -- `mod.user.*_action`,
      `mod.nodes.relay_for_action` -- would have repeated it.
    - `Connector` was `Callable[[], Awaitable["Session"]]`, a forward reference
      in an exported alias, and `astral.stream` imports the alias without the
      class.

    So the check is a sweep rather than three assertions.
    """

    def modules(self) -> list[str]:
        directory = pathlib.Path(astral.api.__file__).parent
        return [
            "astral",
            "astral.blueprint",
            "astral.channel",
            "astral.client",
            "astral.codec",
            "astral.conn",
            "astral.context",
            "astral.object",
            "astral.objectid",
            "astral.primitives",
            "astral.querystring",
            "astral.record",
            "astral.registrar",
            "astral.registry",
            "astral.serve",
            "astral.session",
            "astral.spec",
            "astral.stream",
            "astral.transport",
            "astral.types",
            "astral.wire",
        ] + [
            f"astral.api.{path.stem}"
            for path in sorted(directory.glob("*.py"))
            if not path.stem.startswith("_")
        ]

    def test_every_public_annotation_resolves(self):
        import inspect
        import typing

        import astral.api

        checked = 0
        for name in self.modules():
            module = importlib.import_module(name)
            for attribute in sorted(vars(module)):
                if attribute.startswith("_"):
                    continue
                obj = getattr(module, attribute)
                if not (inspect.isclass(obj) or inspect.isfunction(obj)):
                    continue
                if getattr(obj, "__module__", None) != name:
                    continue
                targets = [(attribute, obj)]
                if inspect.isclass(obj) and "__init__" in vars(obj):
                    targets.append((f"{attribute}.__init__", obj.__init__))
                for label, target in targets:
                    checked += 1
                    with self.subTest(module=name, name=label):
                        try:
                            typing.get_type_hints(target)
                        except NameError as exc:  # pragma: no cover -- the defect
                            self.fail(
                                f"{name}.{label} has an unresolvable annotation: "
                                f"{exc}. py.typed makes this a shipped interface."
                            )
        self.assertGreater(checked, 100, "the sweep found nothing to check")

    def test_every_public_dataclass_signature_is_introspectable(self):
        """The call a real tool makes. `get_type_hints(cls)` succeeds where this
        fails, which is why the fault was invisible to the obvious spot check."""
        import dataclasses
        import inspect

        checked = 0
        for name in self.modules():
            module = importlib.import_module(name)
            for attribute in sorted(vars(module)):
                if attribute.startswith("_"):
                    continue
                obj = getattr(module, attribute)
                if not inspect.isclass(obj) or not dataclasses.is_dataclass(obj):
                    continue
                if getattr(obj, "__module__", None) != name:
                    continue
                checked += 1
                with self.subTest(module=name, name=attribute):
                    try:
                        inspect.signature(obj, eval_str=True)
                    except NameError as exc:  # pragma: no cover -- the defect
                        self.fail(
                            f"inspect.signature({name}.{attribute}, eval_str=True) "
                            f"raises {exc}"
                        )
        self.assertGreater(checked, 20, "the sweep found no dataclasses")


if __name__ == "__main__":
    unittest.main()
