"""Static asset loader for the single-page UI."""

from __future__ import annotations

import mimetypes
import os

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")


def read_static(rel: str) -> bytes | None:
    path = os.path.join(STATIC_DIR, rel)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def content_type(rel: str) -> str:
    guess, _ = mimetypes.guess_type(rel)
    if guess is None:
        return "application/octet-stream"
    if guess.startswith("text/") or guess in ("application/javascript", "image/svg+xml"):
        return f"{guess}; charset=utf-8"
    return guess
