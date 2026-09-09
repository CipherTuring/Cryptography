"""
Console helper for the runnable scripts of the laboratory.

On Windows, `sys.stdout` defaults to the console code page (cp1252 /
cp850), which cannot represent all the UTF-8 text of the messages.
Reconfiguring the output to UTF-8 avoids `UnicodeEncodeError` and
mojibake without affecting Linux or macOS, where it is UTF-8 already.
"""

import sys

__all__ = ["use_utf8_stdout"]


def use_utf8_stdout() -> None:
    """Reconfigure stdout/stderr to UTF-8 if the platform allows it."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            # Redirected or non-reconfigurable stream: not a fatal error.
            pass
