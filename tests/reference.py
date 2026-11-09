"""Reading the reference repositories **at the revision the SDK was read at**.

Five test files used to glob a sibling working tree and assert set equality
against it. That makes the SDK's suite go red whenever somebody pulls the
reference, which is not a fact about this SDK at all: astrald moved from
`074a852b` to `3392926b` in one window, gained `op_delete_token.go`, and the
apphost origin-guard census failed on a file the running node does not even
serve. A verdict that depends on an unpinned sibling checkout will keep doing
that, and at thirteen modules it is thirteen files breaking on every upstream
pull.

So a citation is read the way it is written: `git show <rev>:<path>`. The
revision is the one the module's docstring names, the reference tree's own
working state is irrelevant, and a reference that moves is no longer an event
this suite has an opinion about. Upstream drift becomes a deliberate act -- bump
the pin here, re-read the module, update the prose -- instead of a surprise.

`PINS` holds the revision a module reads by default, and a reader passes `rev`
to read one claim somewhere else. The pin governs every `path:line` in
`astral/api/*.py` at once, so moving it is a re-read of the whole package.

**No module passes `rev` today.** The SDK supports the node at the pins and no
older one, so a claim about another revision has nowhere to live: every citation
resolves at a pin or it is deleted. `rev` stays because a claim named in prose
and never read is prose no test can check, which is how `api/apphost.py` once
carried a security note that had stopped being true.

**Absent is a skip, wrong is a failure.** No clone, no git, or a revision that
was never fetched: skip, because the reference is not part of this repository
and a machine without it must still be able to run the suite. A revision that
*is* present and disagrees with what the module claims: fail, because that is
the SDK making a false statement about the protocol.
"""

from __future__ import annotations

import functools
import pathlib
import subprocess
from typing import Final

ASTRALD: Final = "astrald"
ASTRAL_GO: Final = "astral-go"

PINS: Final[dict[str, tuple[pathlib.Path, str]]] = {
    # The revisions the modules were read against: astrald `a7c773d6`, the
    # merge of astrald pull request #383 (mod/sys: the node state, the manager
    # appointment and `sys.register_manager`), and astral-go `4a3e111c`, the
    # merge of astral-go pull request #175 (`api/sys`), which astrald
    # `a7c773d6` requires. Every `path:line` citation in `astral/api/*.py`
    # resolves at one of these two and none names another revision. Bumping
    # one means re-reading the citations that name it. The record of each
    # earlier bump is this comment's history in `git log -p tests/reference.py`.
    #
    # Bumped from astrald `5b4dde12` / astral-go `2481dd7a`. Every cited line
    # whose text did not change was moved to its new number; every other cited
    # line, and every cited file whose code changed, was re-read. Claims
    # rewritten: the node state and the manager are mod/sys's
    # (`mod/sys/src/state.go`), and every policy setter asks
    # `ConfigureNodeStateAction` alone, which the manager holds through
    # `mod/sys/src/authorizers.go`; the default gate lists `.spec` everywhere
    # and the unclaimed list adds `apphost.bind`, `apphost.register_handler` and
    # `apphost.cancel`; the removed `allow_anonymous` and `anonymous_allowlist`
    # keys no longer stop the node (`checkRemovedKeys` is gone); the apphost
    # census counts seventeen files, fifteen refusing a network origin; the
    # bip137sig and crypto ops' comments read "no named action guards this op".
    # The sys citations, which named a path alone while mod/sys was ahead of
    # the pins, are `path:line` and `test_api_sys.CitationTest` reads them.
    # Surface added: `user.introduce`, `user.contract` and
    # `ERR_INTRODUCE_SELF`, with `User.introduce` and `User.contract`.
    ASTRALD: (pathlib.Path("/home/intern0/work/astralp2p/astrald/master"), "a7c773d6"),
    ASTRAL_GO: (pathlib.Path("/home/intern0/work/astralp2p/astral-go/main"), "4a3e111c"),
}


class Unavailable(Exception):
    """The reference is not on this machine, or the pin was never fetched."""


def _git(root: pathlib.Path, *args: str) -> str:
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        raise Unavailable(f"{root}: {exc}") from exc
    if done.returncode != 0:  # pragma: no cover -- absent path or absent rev
        raise Unavailable(
            f"git {' '.join(args)} in {root}: "
            f"{done.stderr.decode('utf-8', 'replace').strip()}"
        )
    return done.stdout.decode("utf-8", "replace")


@functools.lru_cache(maxsize=None)
def _resolve(repo: str) -> tuple[pathlib.Path, str]:
    root, rev = PINS[repo]
    if not (root / ".git").exists() and not root.is_dir():  # pragma: no cover
        raise Unavailable(f"{root} is not present")
    # Resolved once so a bad pin reports itself as a pin problem rather than as
    # a missing file, and so every later read is a plain object lookup.
    return root, _git(root, "rev-parse", f"{rev}^{{commit}}").strip()


@functools.lru_cache(maxsize=None)
def _commit(repo: str, rev: str | None) -> tuple[pathlib.Path, str]:
    """The reference's root and the commit `rev` names, or the pin for `None`.

    Resolved here for the same reason the pin is: an unfetched revision reports
    itself as a revision problem rather than as a missing file.
    """
    root, pinned = _resolve(repo)
    if rev is None:
        return root, pinned
    return root, _git(root, "rev-parse", f"{rev}^{{commit}}").strip()


@functools.lru_cache(maxsize=None)
def read(repo: str, path: str, rev: str | None = None) -> str:
    """One file, as it stood at `rev`, or at the pin. `Unavailable` when absent."""
    root, at = _commit(repo, rev)
    return _git(root, "show", f"{at}:{path}")


@functools.lru_cache(maxsize=None)
def listdir(repo: str, directory: str, rev: str | None = None) -> tuple[str, ...]:
    """The file names directly under `directory` at `rev`, or at the pin, sorted.

    Names only, one level, no trees: the census callers want is "which `op_*.go`
    files existed", and a recursive walk would answer a different question.
    """
    root, at = _commit(repo, rev)
    prefix = directory.rstrip("/") + "/"
    names = []
    for line in _git(root, "ls-tree", "--name-only", at, prefix).splitlines():
        name = line.strip()
        if not name or name.endswith("/"):
            continue
        names.append(name[len(prefix) :])
    return tuple(sorted(n for n in names if "/" not in n))


def repo_root(repo: str) -> pathlib.Path:
    return _resolve(repo)[0]


def pin(repo: str) -> str:
    """The resolved commit the citations were written against."""
    return _resolve(repo)[1]


def cited_line(repo: str, path: str, number: int, rev: str | None = None) -> str:
    """The 1-indexed line a `path:line` citation names, at `rev` or at the pin."""
    return read(repo, path, rev).splitlines()[number - 1]
