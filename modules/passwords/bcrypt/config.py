from __future__ import annotations


ALGORITHM_NAME = "bcrypt"

DEFAULT_ROUNDS = 12

MIN_ROUNDS = 4
MAX_ROUNDS = 31

MAX_PASSWORD_BYTES = 72

SUPPORTED_PREFIXES = (
    "$2a$",
    "$2b$",
    "$2y$",
)