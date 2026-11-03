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
    # The revisions the modules were read against: astrald `5b4dde12`, the
    # head of astrald branch `intern0/dev/node-manager-bootstrap` (the apphost
    # gate, node states and manager appointment), and astral-go `2481dd7a`, the
    # merge of astral-go pull request #171, which astrald `5b4dde12` requires.
    # Every `path:line` citation in `astral/api/*.py` resolves at one of these
    # two and none names another revision. Bumping one means re-reading the
    # citations that name it. The record of each earlier bump is this comment's
    # history in `git log -p tests/reference.py`.
    #
    # Bumped from astrald `9c466cf3` / astral-go `08ead7ce`. The range carries
    # astrald's app-signers and coldcard-removal merges besides the bootstrap
    # commit. Re-read at the bump, every cited astrald file that differs
    # between the two: `mod/apphost/src` (`config.go`, `guest.go`,
    # `http_query_handler.go`, `loader.go`, `op_register.go`,
    # `op_set_app_register_policy.go`, `register_policy.go`, `setup_guard.go`
    # (deleted), `gate.go` and `op_register_manager.go` (added)),
    # `mod/apphost/register_policy.go`, `mod/user/module.go`, `mod/user/src`
    # (`authorize_user_or_node.go`, `authorizers.go`, `config.go`,
    # `contracts.go`, `op_bootstrap.go`, `op_info.go`, `op_join.go`,
    # `op_set_swarm_policy.go`, `swarm_policy.go`), `mod/crypto/src/module.go`
    # and `op_register_signer.go` (added), `mod/crypto/errors.go`,
    # `mod/auth/src/sign_contract_guard.go`, `mod/shell/src/op_spec.go` and
    # `lib/policyconf/setting.go` (added); in astral-go,
    # `api/apphost/client/register.go`, `api/apphost/errors.go`,
    # `api/apphost/module.go`, `api/user/info.go` and
    # `api/apphost/register_manager_request.go` (added). Claims rewritten: the
    # gate replaces the tokenless allowlist and binds a session with a token to
    # the node state's list as well, and its removed keys stop the node;
    # `user.info` answers `mod.user.info` with `State` and `Manager` in every
    # state, so `no active contract` is no longer its answer; the app register,
    # swarm join and swarm invite policies fall back to a config value whose
    # default is `reject_all`; the policy setters, `user.bootstrap` and
    # `user.join` admit the manager; the apphost census counts eighteen files.
    # Surface added: `mod.user.info`'s `State` and `Manager`, the `STATE_*`
    # constants, `apphost.register_manager`, `mod.apphost.register_manager_request`,
    # `mod.apphost.policy_binding`, `POLICY_*` and `ERR_NOT_FRESH`. Surface not
    # added: `crypto.register_signer` and its types, which
    # `test_api_crypto.AstraldParityTest` names.
    ASTRALD: (pathlib.Path("/home/intern0/work/astralp2p/astrald/master"), "5b4dde12"),
    ASTRAL_GO: (pathlib.Path("/home/intern0/work/astralp2p/astral-go/main"), "2481dd7a"),
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
