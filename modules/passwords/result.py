from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CrackProgress:
    target_name: str

    source_name: str

    file: Path

    attempts: int

    elapsed_seconds: float

    attempts_per_second: float


@dataclass(frozen=True, slots=True)
class CrackResult:
    target_name: str

    algorithm: str

    found: bool

    password: str | None

    source_name: str | None

    file: Path | None

    attempts: int

    elapsed_seconds: float

    attempts_per_second: float