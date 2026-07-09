"""The ``objects`` protocol: typed object storage and retrieval.

Reference: ``protocols/objects/``. ``read`` streams raw bytes (no astral
framing); ``describe`` streams structured descriptors best decoded over a JSON
transport.
"""

from __future__ import annotations

from typing import Any, List, Optional, Union

from ..objectid import ObjectID
from . import Protocol

__all__ = ["Objects"]


def _id_str(object_id: Union[str, ObjectID]) -> str:
    return str(object_id)


class Objects(Protocol):
    def read(
        self,
        object_id: Union[str, ObjectID],
        *,
        offset: int = 0,
        limit: int = 0,
        repo: Optional[str] = None,
    ) -> bytes:
        """Read an object's raw bytes (the response body is unframed)."""
        args: dict = {"id": _id_str(object_id)}
        if offset:
            args["offset"] = offset
        if limit:
            args["limit"] = limit
        if repo is not None:
            args["repo"] = repo
        with self.client.query("objects.read", args) as stream:
            return stream.read()

    def describe(
        self, object_id: Union[str, ObjectID], *, only: Optional[str] = None
    ) -> List[Any]:
        """Collect descriptor objects for ``object_id``."""
        args: dict = {"id": _id_str(object_id)}
        if only is not None:
            args["only"] = only
        return [obj.value for obj in self.client.call("objects.describe", args)]

    def contains(self, object_id: Union[str, ObjectID]) -> bool:
        """Return whether the object is available locally."""
        result = self.client.call_one("objects.contains", {"id": _id_str(object_id)})
        return bool(result)

    def get_type(self, object_id: Union[str, ObjectID]) -> Any:
        """Return the object's type."""
        return self.client.call_one("objects.get_type", {"id": _id_str(object_id)})
