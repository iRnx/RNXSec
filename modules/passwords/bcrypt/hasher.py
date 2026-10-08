from __future__ import annotations

import bcrypt

from modules.passwords.bcrypt.config import (
    DEFAULT_ROUNDS,
    MAX_PASSWORD_BYTES,
    MAX_ROUNDS,
    MIN_ROUNDS,
)


class BcryptHasher:
    """
    Responsável exclusivamente pela geração
    de hashes bcrypt.
    """

    @classmethod
    def hash_password(
        cls,
        password: str,
        rounds: int = DEFAULT_ROUNDS,
    ) -> str:
        if password == "":
            raise ValueError(
                "A senha não pode ser vazia."
            )

        cls._validate_rounds(
            rounds
        )

        password_bytes = (
            cls.password_to_bytes(
                password
            )
        )

        salt = bcrypt.gensalt(
            rounds=rounds
        )

        password_hash = bcrypt.hashpw(
            password_bytes,
            salt,
        )

        return password_hash.decode(
            "utf-8"
        )

    @staticmethod
    def password_to_bytes(
        password: str,
    ) -> bytes:
        """
        Mantém compatibilidade com o comportamento
        histórico do projeto.

        bcrypt trabalha com no máximo 72 bytes.
        """

        return (
            password
            .encode("utf-8")
            [:MAX_PASSWORD_BYTES]
        )

    @staticmethod
    def _validate_rounds(
        rounds: int,
    ) -> None:
        if not isinstance(
            rounds,
            int,
        ):
            raise TypeError(
                "rounds precisa ser inteiro."
            )

        if not (
            MIN_ROUNDS
            <= rounds
            <= MAX_ROUNDS
        ):
            raise ValueError(
                "rounds precisa estar entre "
                f"{MIN_ROUNDS} e {MAX_ROUNDS}."
            )