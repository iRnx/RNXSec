from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PasswordHashTarget:
    name: str
    algorithm: str
    hash_value: str