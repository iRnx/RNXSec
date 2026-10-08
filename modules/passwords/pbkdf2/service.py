from __future__ import annotations

from modules.passwords.base import (
    PasswordAlgorithm,
)
from modules.passwords.pbkdf2.config import (
    ALGORITHM_NAME,
    DEFAULT_ITERATIONS,
)
from modules.passwords.pbkdf2.hasher import (
    PBKDF2Hasher,
)
from modules.passwords.pbkdf2.verifier import (
    PBKDF2Verifier,
    PreparedPBKDF2Hash,
)


class PBKDF2Service(
    PasswordAlgorithm
):
    """
    Fachada pública do módulo PBKDF2.
    """

    name = ALGORITHM_NAME

    def prepare_hash(
        self,
        hash_value: str,
    ) -> PreparedPBKDF2Hash:
        return (
            PBKDF2Verifier.prepare_hash(
                hash_value
            )
        )

    def verify_candidate(
        self,
        candidate: str,
        prepared_hash: PreparedPBKDF2Hash,
    ) -> bool:
        return (
            PBKDF2Verifier.verify_candidate(
                candidate=candidate,
                prepared_hash=prepared_hash,
            )
        )

    @staticmethod
    def hash_password(
        password: str,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> str:
        return (
            PBKDF2Hasher.hash_password(
                password=password,
                iterations=iterations,
            )
        )

    def verify_password(
        self,
        password: str,
        hash_value: str,
    ) -> bool:
        prepared_hash = (
            self.prepare_hash(
                hash_value
            )
        )

        return self.verify_candidate(
            candidate=password,
            prepared_hash=prepared_hash,
        )