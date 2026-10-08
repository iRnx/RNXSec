from __future__ import annotations

from modules.passwords.base import PasswordAlgorithm
from modules.passwords.bcrypt.config import (
    ALGORITHM_NAME,
    DEFAULT_ROUNDS,
)
from modules.passwords.bcrypt.hasher import (
    BcryptHasher,
)
from modules.passwords.bcrypt.verifier import (
    BcryptVerifier,
)


class BcryptService(
    PasswordAlgorithm
):
    """
    Fachada pública do módulo bcrypt.
    """

    name = ALGORITHM_NAME

    def prepare_hash(
        self,
        hash_value: str,
    ) -> str:
        return (
            BcryptVerifier.prepare_hash(
                hash_value
            )
        )

    def verify_candidate(
        self,
        candidate: str,
        prepared_hash: str,
    ) -> bool:
        return (
            BcryptVerifier.verify_candidate(
                candidate,
                prepared_hash,
            )
        )

    @staticmethod
    def hash_password(
        password: str,
        rounds: int = DEFAULT_ROUNDS,
    ) -> str:
        return (
            BcryptHasher.hash_password(
                password=password,
                rounds=rounds,
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