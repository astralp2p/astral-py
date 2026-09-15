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
to read one claim somewhere else. The two are not the same act: the pin governs
every `path:line` in `astral/api/*.py` at once, so moving it is a re-read of the
whole package, while a module that documents one merged upstream change names
that change's revision in its own prose and reads it there. Without `rev` such a
claim is prose no test can check, which is how `api/apphost.py` carried a
security note that had stopped being true.

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
    # The revisions the Tier-1 modules were read against. Every `path:line`
    # citation in `astral/api/*.py` resolves at one of these two and nowhere
    # else, so bumping one means re-reading the citations that name it.
    ASTRALD: (pathlib.Path("/home/intern0/work/astralp2p/astrald/master"), "074a852b"),
    ASTRAL_GO: (pathlib.Path("/home/intern0/work/astralp2p/astral-go/main"), "5c18d9c"),
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
