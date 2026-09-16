"""
Helper that writes every result twice.

Each run produces a `.txt` meant to be read and quoted in the report,
and a `.json` holding the same data in raw form, so that tables and
plots can be regenerated without spending another fifty minutes running
the benchmark. The two always share the same stem.
"""

import json
from pathlib import Path
from typing import Any

__all__ = ["RESULTS_DIR", "Report"]

# benchmarks/report.py -> aes_lab_3/results
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


class Report:
    """Accumulates text lines and writes them next to their JSON version."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.lines: list[str] = []
        self.data: dict[str, Any] = {}
        self.rule("=")
        self.line(title)
        self.rule("=")

    def line(self, text: str = "") -> "Report":
        self.lines.append(text)
        return self

    def rule(self, char: str = "-", width: int = 78) -> "Report":
        self.lines.append(char * width)
        return self

    def section(self, title: str) -> "Report":
        return self.line().line(title).rule("-", len(title))

    def render(self) -> str:
        return "\n".join(self.lines) + "\n"

    def emit(self, stem: str, echo: bool = True) -> tuple[Path, Path]:
        """Write `results/<stem>.txt` and `results/<stem>.json` in UTF-8."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        text_path = RESULTS_DIR / f"{stem}.txt"
        json_path = RESULTS_DIR / f"{stem}.json"
        text_path.write_text(self.render(), encoding="utf-8")
        json_path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        if echo:
            print(self.render(), end="")
            print(f"\n-> {text_path}\n-> {json_path}")
        return text_path, json_path
