"""
Helpers shared by the experiment scripts.

Every experiment writes two artifacts to `results/`: a readable `.txt`
that is quoted in the report, and a `.json` with the same data in raw
form, so that tables can be regenerated without running the experiment
again.
"""

import json
from pathlib import Path
from typing import Any

__all__ = [
    "RESULTS_DIR",
    "blocks_of",
    "hamming_bytes",
    "hamming_blocks",
    "printable",
    "flip_bit",
    "Report",
]

# des_lab_2/experiments/common.py -> des_lab_2/results
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def blocks_of(data: bytes, block_size: int = 8) -> list[bytes]:
    """Split `data` into blocks, tolerating an incomplete last block."""
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def hamming_bytes(a: bytes, b: bytes) -> int:
    """Number of differing bits between two sequences of equal length."""
    if len(a) != len(b):
        raise ValueError("las secuencias deben tener la misma longitud")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def hamming_blocks(a: bytes, b: bytes, block_size: int = 8) -> list[int]:
    """Differing bits, block by block, between two messages of equal length."""
    return [
        hamming_bytes(x, y)
        for x, y in zip(blocks_of(a, block_size), blocks_of(b, block_size))
    ]


def printable(data: bytes) -> str:
    """ASCII rendering of `data`, with '.' for the non-printable bytes."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def flip_bit(data: bytes, byte_index: int, bit_index: int) -> bytes:
    """
    Return a copy of `data` with a single bit flipped.

    `bit_index` counts from the most significant bit of the byte
    (bit 0 = MSB), which is the convention used in the report.
    """
    if not 0 <= byte_index < len(data):
        raise ValueError(f"byte_index fuera de rango: {byte_index}")
    if not 0 <= bit_index < 8:
        raise ValueError(f"bit_index debe estar en [0, 8): {bit_index}")
    out = bytearray(data)
    out[byte_index] ^= 1 << (7 - bit_index)
    return bytes(out)


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
