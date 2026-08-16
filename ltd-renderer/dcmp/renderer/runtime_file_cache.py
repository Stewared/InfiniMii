"""Process-local cache for immutable, checked renderer evidence files.

The cache never establishes trust: callers still compare the returned digest
or parsed document with their checked contract.  It only avoids repeating the
same read, UTF-8 decode, JSON parse, or SHA-256 pass while a file's strong stat
identity is unchanged.  Nothing is persisted across Python processes or
renderer revisions.
"""

from __future__ import annotations

import ctypes
import copy
import hashlib
import json
import os
import stat as stat_module
import threading
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

if os.name == "nt":
    from ctypes import wintypes

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _create_file = _kernel32.CreateFileW
    _create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _create_file.restype = wintypes.HANDLE
    _get_file_information = _kernel32.GetFileInformationByHandleEx
    _get_file_information.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _get_file_information.restype = wintypes.BOOL
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = [wintypes.HANDLE]
    _close_handle.restype = wintypes.BOOL


def _platform_change_token(path: Path, fallback: int) -> int:
    """Return metadata change time, including NTFS ChangeTime on Windows."""

    if os.name != "nt":
        return fallback
    handle = _create_file(
        str(path),
        0x0080,  # FILE_READ_ATTRIBUTES
        0x0007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        None,
        3,  # OPEN_EXISTING
        0,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = _FileBasicInfo()
        if not _get_file_information(
            handle,
            0,  # FileBasicInfo
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(information.change_time)
    finally:
        _close_handle(handle)


@dataclass(frozen=True)
class FileState:
    """Resolved path plus mutation-sensitive regular-file stat identity."""

    resolved_path: str
    device: int
    inode: int
    mode: int
    byte_length: int
    modified_ns: int
    changed_ns: int
    platform_change_token: int


@dataclass(frozen=True)
class RuntimeFileCacheInfo:
    byte_hits: int
    byte_misses: int
    text_hits: int
    text_misses: int
    json_hits: int
    json_misses: int
    sha256_hits: int
    sha256_misses: int
    invalidations: int
    state_retries: int
    evictions: int
    request_match_hits: int
    request_match_misses: int
    resident_states: int
    max_resident_states: int


_lock = threading.RLock()
# One production classic request authenticates roughly 630 distinct evidence
# files.  Keep one complete working set resident without letting arbitrary
# request paths grow the process indefinitely.
MAX_RESIDENT_STATES = 768
MAX_REQUEST_MATCHES = 1_024
_current_state: OrderedDict[str, FileState] = OrderedDict()
_bytes: dict[FileState, bytes] = {}
_text: dict[tuple[FileState, str], str] = {}
_json: dict[FileState, Any] = {}
_sha256: dict[FileState, str] = {}
_MISSING = object()
_request_local = threading.local()
_counters = {
    "byte_hits": 0,
    "byte_misses": 0,
    "text_hits": 0,
    "text_misses": 0,
    "json_hits": 0,
    "json_misses": 0,
    "sha256_hits": 0,
    "sha256_misses": 0,
    "invalidations": 0,
    "state_retries": 0,
    "evictions": 0,
    "request_match_hits": 0,
    "request_match_misses": 0,
}


@contextmanager
def request_scope() -> Iterator[None]:
    """Memoize successful checked identities inside one serial render request.

    The memo is deliberately thread-local, bounded by the request lifetime,
    and never carries trust into a later request.  A first lookup still does
    the complete strong before/hash/after validation.  Every repeated contract
    takes a fresh mutation-sensitive state snapshot (including NTFS ChangeTime)
    before reusing the digest result.  Nested scopes share their outer memo so
    helper layers do not accidentally weaken the boundary.
    """

    depth = int(getattr(_request_local, "depth", 0))
    if depth == 0:
        _request_local.matches = OrderedDict()
    _request_local.depth = depth + 1
    try:
        yield
    finally:
        remaining = int(getattr(_request_local, "depth", 1)) - 1
        if remaining <= 0:
            _request_local.__dict__.clear()
        else:
            _request_local.depth = remaining


def _snapshot(path: Path | str) -> tuple[Path, FileState]:
    resolved = Path(path).resolve(strict=True)
    value = resolved.stat()
    if not stat_module.S_ISREG(value.st_mode):
        raise OSError(f"runtime evidence is not a regular file: {resolved}")
    return resolved, FileState(
        resolved_path=os.path.normcase(str(resolved)),
        device=int(value.st_dev),
        inode=int(value.st_ino),
        mode=int(value.st_mode),
        byte_length=int(value.st_size),
        modified_ns=int(value.st_mtime_ns),
        changed_ns=int(value.st_ctime_ns),
        platform_change_token=_platform_change_token(
            resolved, int(value.st_ctime_ns)
        ),
    )


def _drop_state_locked(state: FileState) -> None:
    """Drop every cached representation of one file state while holding the lock."""

    _bytes.pop(state, None)
    _json.pop(state, None)
    _sha256.pop(state, None)
    for key in tuple(_text):
        if key[0] == state:
            _text.pop(key, None)


def _observe(state: FileState) -> None:
    """Evict the prior identity for this path before accepting a new state."""

    with _lock:
        prior = _current_state.get(state.resolved_path)
        if prior == state:
            _current_state.move_to_end(state.resolved_path)
            return
        if prior is not None:
            _drop_state_locked(prior)
            _counters["invalidations"] += 1
        _current_state[state.resolved_path] = state
        _current_state.move_to_end(state.resolved_path)
        while len(_current_state) > MAX_RESIDENT_STATES:
            _, evicted = _current_state.popitem(last=False)
            _drop_state_locked(evicted)
            _counters["evictions"] += 1


def _stable_snapshot(path: Path | str) -> tuple[Path, FileState]:
    resolved, state = _snapshot(path)
    _observe(state)
    return resolved, state


def _read_stable_bytes(path: Path | str) -> tuple[bytes, FileState]:
    for _ in range(3):
        resolved, before = _stable_snapshot(path)
        with _lock:
            cached = _bytes.get(before)
        if cached is not None:
            _, after = _snapshot(resolved)
            if after == before:
                with _lock:
                    _counters["byte_hits"] += 1
                return cached, before
        else:
            payload = resolved.read_bytes()
            _, after = _snapshot(resolved)
            if after == before and len(payload) == before.byte_length:
                with _lock:
                    if _current_state.get(before.resolved_path) == before:
                        _bytes[before] = payload
                    _counters["byte_misses"] += 1
                return payload, before
        with _lock:
            _counters["state_retries"] += 1
        _observe(after)
    raise OSError(f"runtime evidence changed repeatedly while reading: {path}")


def read_bytes(path: Path | str) -> bytes:
    """Return exact bytes for one stable file state."""

    return _read_stable_bytes(path)[0]


def read_text(path: Path | str, *, encoding: str = "utf-8") -> str:
    """Decode one stable byte payload once per encoding."""

    payload, state = _read_stable_bytes(path)
    key = (state, encoding)
    with _lock:
        cached = _text.get(key)
        if cached is not None:
            _counters["text_hits"] += 1
            return cached
    value = payload.decode(encoding)
    with _lock:
        if _current_state.get(state.resolved_path) == state:
            _text[key] = value
        _counters["text_misses"] += 1
    return value


def load_json_shared(path: Path | str) -> Any:
    """Load a shared JSON evidence document that callers promise not to mutate."""

    payload, state = _read_stable_bytes(path)
    with _lock:
        cached = _json.get(state, _MISSING)
        if cached is not _MISSING:
            _counters["json_hits"] += 1
            return cached
    value = json.loads(payload)
    with _lock:
        if _current_state.get(state.resolved_path) == state:
            _json[state] = value
        _counters["json_misses"] += 1
    return value


def load_json(path: Path | str) -> Any:
    """Load JSON defensively so caller mutation cannot poison the shared cache."""

    return copy.deepcopy(load_json_shared(path))


def _read_uncached_stable_bytes(path: Path | str) -> bytes:
    """Read one stable state without retaining request-scoped file data."""

    for _ in range(3):
        resolved, before = _snapshot(path)
        payload = resolved.read_bytes()
        _, after = _snapshot(resolved)
        if after == before and len(payload) == before.byte_length:
            return payload
        with _lock:
            _counters["state_retries"] += 1
    raise OSError(f"runtime request file changed repeatedly while reading: {path}")


def load_json_uncached(path: Path | str) -> Any:
    """Load stable request JSON without adding its path or payload to the cache."""

    return json.loads(_read_uncached_stable_bytes(path))


def sha256(path: Path | str) -> str:
    """Return SHA-256 for one stable file state, hashing that state once."""

    for _ in range(3):
        resolved, before = _stable_snapshot(path)
        with _lock:
            cached = _sha256.get(before)
            payload = _bytes.get(before)
        if cached is not None:
            _, after = _snapshot(resolved)
            if after == before:
                with _lock:
                    _counters["sha256_hits"] += 1
                return cached
        if payload is not None:
            digest = hashlib.sha256(payload).hexdigest()
        else:
            hasher = hashlib.sha256()
            with resolved.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    hasher.update(block)
            digest = hasher.hexdigest()
        _, after = _snapshot(resolved)
        if after == before:
            with _lock:
                if _current_state.get(before.resolved_path) == before:
                    _sha256[before] = digest
                _counters["sha256_misses"] += 1
            return digest
        with _lock:
            _counters["state_retries"] += 1
        _observe(after)
    raise OSError(f"runtime evidence changed repeatedly while hashing: {path}")


def matches_file(
    path: Path | str,
    *,
    byte_length: int,
    sha256_digest: str,
) -> Path | None:
    """Return the resolved path iff one stable state has the checked identity."""

    request_matches = getattr(_request_local, "matches", None)
    requested_path = os.path.normcase(os.path.abspath(os.fspath(path)))
    request_key = (requested_path, int(byte_length), str(sha256_digest))
    if request_matches is not None:
        cached_request = request_matches.get(request_key)
        if cached_request is not None:
            cached_resolved, cached_state = cached_request
            try:
                current_resolved, current_state = _snapshot(path)
            except (FileNotFoundError, NotADirectoryError, OSError):
                request_matches.pop(request_key, None)
                return None
            if current_resolved == cached_resolved and current_state == cached_state:
                request_matches.move_to_end(request_key)
                with _lock:
                    _counters["request_match_hits"] += 1
                return cached_resolved
            request_matches.pop(request_key, None)
            _observe(current_state)
        with _lock:
            _counters["request_match_misses"] += 1

    for _ in range(3):
        try:
            resolved, before = _stable_snapshot(path)
        except (FileNotFoundError, NotADirectoryError, OSError):
            return None
        if before.byte_length != int(byte_length):
            return None
        with _lock:
            actual = _sha256.get(before)
            payload = _bytes.get(before)
        if actual is None:
            if payload is not None:
                actual = hashlib.sha256(payload).hexdigest()
            else:
                hasher = hashlib.sha256()
                with resolved.open("rb") as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        hasher.update(block)
                actual = hasher.hexdigest()
        _, after = _snapshot(resolved)
        if after == before:
            with _lock:
                if before not in _sha256:
                    if _current_state.get(before.resolved_path) == before:
                        _sha256[before] = actual
                    _counters["sha256_misses"] += 1
                else:
                    _counters["sha256_hits"] += 1
            if actual != str(sha256_digest):
                return None
            if request_matches is not None:
                request_matches[request_key] = (resolved, before)
                request_matches.move_to_end(request_key)
                while len(request_matches) > MAX_REQUEST_MATCHES:
                    request_matches.popitem(last=False)
            return resolved
        with _lock:
            _counters["state_retries"] += 1
        _observe(after)
    raise OSError(f"runtime evidence changed repeatedly while validating: {path}")


def clear() -> None:
    """Clear this process's non-authoritative acceleration state."""

    with _lock:
        _current_state.clear()
        _bytes.clear()
        _text.clear()
        _json.clear()
        _sha256.clear()
        for key in _counters:
            _counters[key] = 0


def cache_info() -> RuntimeFileCacheInfo:
    with _lock:
        return RuntimeFileCacheInfo(
            **_counters,
            resident_states=len(_current_state),
            max_resident_states=MAX_RESIDENT_STATES,
        )


__all__ = [
    "FileState",
    "MAX_REQUEST_MATCHES",
    "MAX_RESIDENT_STATES",
    "RuntimeFileCacheInfo",
    "cache_info",
    "clear",
    "load_json",
    "load_json_shared",
    "load_json_uncached",
    "matches_file",
    "read_bytes",
    "read_text",
    "request_scope",
    "sha256",
]
