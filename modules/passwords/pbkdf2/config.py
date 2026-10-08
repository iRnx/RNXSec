from __future__ import annotations


ALGORITHM_NAME = "pbkdf2"

ENCODED_ALGORITHM_NAME = "pbkdf2_sha256"

DIGEST_NAME = "sha256"

# Valor propositalmente amigável para laboratório.
#
# Não representa uma recomendação para produção.
# Em produção, deixe frameworks como Django aplicarem
# sua política atual de hashing.
DEFAULT_ITERATIONS = 100_000

MIN_ITERATIONS = 1

# Proteção contra um valor absurdo digitado por engano.
MAX_ITERATIONS = 10_000_000

SALT_LENGTH = 22

DERIVED_KEY_LENGTH = 32