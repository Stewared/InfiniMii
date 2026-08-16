#!/usr/bin/env python3
"""Persistent JSON-lines host for the deterministic LTD renderer.

The image pipeline remains ``render_mii.py``.  This host only keeps its Python
interpreter and mutation-sensitive evidence caches alive between independent
requests.  It does not weaken any renderer validation and it deliberately does
not describe itself as a native renderer.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from renderer import render_mii, runtime_file_cache  # noqa: E402


PROTOCOL = "infinimii-ltd-render-worker"
PROTOCOL_VERSION = 1
MAX_CAPTURE_CHARS = 512 * 1024
MAX_REQUEST_CHARS = 64 * 1024
REQUIRED_KEYS = frozenset(
    {
        "protocol",
        "protocol_version",
        "request_id",
        "input",
        "asset_root",
        "build_active_parts",
        "output_dir",
        "size",
        "view",
        "supersample_factor",
    }
)
OPTIONAL_KEYS = frozenset({"presentation_context"})


class WorkerRequestError(ValueError):
    """Raised for a malformed local worker request."""


class _BoundedTextCapture(io.StringIO):
    def write(self, value: str) -> int:
        text = str(value)
        remaining = MAX_CAPTURE_CHARS - self.tell()
        if remaining > 0:
            super().write(text[:remaining])
        return len(text)


def _write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":"), ensure_ascii=True) + "\n")
    sys.stdout.flush()


def _request_path(request: dict[str, Any], key: str) -> Path:
    value = request.get(key)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise WorkerRequestError(f"{key} must be a nonempty path string")
    path = Path(value)
    if not path.is_absolute():
        raise WorkerRequestError(f"{key} must be absolute")
    return path


def _validate_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise WorkerRequestError("request must be a JSON object")
    keys = frozenset(request)
    missing = REQUIRED_KEYS - keys
    unknown = keys - REQUIRED_KEYS - OPTIONAL_KEYS
    if missing:
        raise WorkerRequestError(f"request is missing keys: {', '.join(sorted(missing))}")
    if unknown:
        raise WorkerRequestError(f"request has unknown keys: {', '.join(sorted(unknown))}")
    if request.get("protocol") != PROTOCOL or request.get("protocol_version") != PROTOCOL_VERSION:
        raise WorkerRequestError("worker protocol identity does not match")
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
        raise WorkerRequestError("request_id must be a nonempty string of at most 128 characters")
    for key in ("input", "asset_root", "build_active_parts", "output_dir"):
        _request_path(request, key)
    if "presentation_context" in request:
        _request_path(request, "presentation_context")
    size = request.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 128 <= size <= 1024:
        raise WorkerRequestError("size must be an integer in 128..1024")
    if request.get("view") not in {"portrait", "full-body"}:
        raise WorkerRequestError("view must be portrait or full-body")
    if request.get("supersample_factor") != 1:
        raise WorkerRequestError("the production worker requires supersample_factor 1")
    return request


def _render(request: dict[str, Any]) -> dict[str, Any]:
    capture_stdout = _BoundedTextCapture()
    capture_stderr = _BoundedTextCapture()
    original_argv = sys.argv
    started = time.perf_counter()
    code = 1
    restart_required = False
    try:
        arguments = [
            str(Path(render_mii.__file__).resolve()),
            str(_request_path(request, "input")),
            "--asset-root",
            str(_request_path(request, "asset_root")),
            "--build-active-parts",
            str(_request_path(request, "build_active_parts")),
            "--output-dir",
            str(_request_path(request, "output_dir")),
            "--size",
            str(request["size"]),
            "--view",
            str(request["view"]),
            "--supersample-factor",
            "1",
        ]
        if "presentation_context" in request:
            arguments.extend(
                ["--presentation-context", str(_request_path(request, "presentation_context"))]
            )
        sys.argv = arguments
        with (
            runtime_file_cache.request_scope(),
            contextlib.redirect_stdout(capture_stdout),
            contextlib.redirect_stderr(capture_stderr),
        ):
            result = render_mii.main()
        code = int(result)
    except SystemExit as error:
        code = int(error.code) if isinstance(error.code, int) else 1
        if error.code not in (None, 0):
            capture_stderr.write(f"render_mii exited with {error.code!r}\n")
    except Exception as error:  # Renderer errors are returned to the existing Node classifier.
        code = 1
        traceback.print_exc(file=capture_stderr)
        restart_required = (
            isinstance(error, RuntimeError)
            and "one renderer process cannot switch ShareMii texture-cache targets" in str(error)
        )
    finally:
        sys.argv = original_argv
    return {
        "protocol": PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request["request_id"],
        "code": code,
        "stdout": capture_stdout.getvalue(),
        "stderr": capture_stderr.getvalue(),
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "restart_required": restart_required,
    }


def main() -> int:
    _write_message(
        {
            "protocol": PROTOCOL,
            "protocol_version": PROTOCOL_VERSION,
            "kind": "ready",
            "pid": os.getpid(),
            "renderer": "python-portable-persistent-host",
            "native": False,
        }
    )
    for raw_line in sys.stdin:
        request_id: str | None = None
        try:
            if len(raw_line) > MAX_REQUEST_CHARS:
                raise WorkerRequestError("request line is too large")
            request = json.loads(raw_line)
            if isinstance(request, dict) and isinstance(request.get("request_id"), str):
                request_id = request["request_id"]
            _write_message(_render(_validate_request(request)))
        except (json.JSONDecodeError, WorkerRequestError) as error:
            _write_message(
                {
                    "protocol": PROTOCOL,
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": request_id,
                    "code": 2,
                    "stdout": "",
                    "stderr": f"WorkerRequestError: {error}\n",
                    "elapsed_ms": 0.0,
                    "restart_required": False,
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
