from dataclasses import dataclass
import hashlib
import posixpath
import time


CHANNELS = ("stable", "testing")
MUTABLE_NAMES = {"summary", "summary.sig", "summary.detached.sig", "config", "luminus-imports.json",
                 "luminus-imports.json.sig"}


class ImportError(Exception):
    pass


@dataclass(frozen=True)
class Upload:
    key: str
    content: bytes
    mutable: bool
    method: str = "PUT"

    @property
    def sha256(self):
        return hashlib.sha256(self.content).hexdigest()


def _checked_key(channel, key):
    if channel not in CHANNELS or not isinstance(key, str) or not key.startswith(channel + "/"):
        raise ImportError("object key is outside the selected channel")
    if "\\" in key or "\x00" in key:
        raise ImportError("object key contains an unsafe path")
    pieces = key.split("/")
    if any(piece in ("", ".", "..") for piece in pieces) or posixpath.normpath(key) != key:
        raise ImportError("object key contains an unsafe path")
    return key


def is_mutable_key(key):
    path = key.split("/", 1)[-1]
    return (path in MUTABLE_NAMES or path.startswith("refs/") or path.startswith("appstream/")
            or path.endswith(".commitmeta") or path.startswith("summary"))


def build_upload_plan(channel, files):
    if channel not in CHANNELS:
        raise ImportError("channel is not allowed")
    uploads = []
    for key, content in files.items():
        _checked_key(channel, key)
        if not isinstance(content, bytes):
            raise ImportError("upload content must be bytes")
        uploads.append(Upload(key, content, is_mutable_key(key)))
    return sorted(uploads, key=lambda item: (item.mutable, item.key))


def publish_uploads(channel, files, storage, public_verify, *, expires_at=None,
                    minimum_mutable_budget=0, clock=time.time):
    plan = build_upload_plan(channel, files)
    immutable = [item for item in plan if not item.mutable]
    mutable = [item for item in plan if item.mutable]
    for item in immutable:
        if expires_at is not None and clock() >= expires_at:
            raise ImportError("temporary credentials expired during immutable uploads")
        storage.put(item.key, item.content)
        if not public_verify(item.key, item.content):
            raise ImportError("public immutable-object verification failed")
    if mutable and expires_at is not None and expires_at - clock() < minimum_mutable_budget:
        raise ImportError("insufficient temporary credential lifetime for mutable metadata")
    for item in mutable:
        if expires_at is not None and clock() >= expires_at:
            raise ImportError("temporary credentials expired during mutable uploads")
        storage.put(item.key, item.content)
    return plan
