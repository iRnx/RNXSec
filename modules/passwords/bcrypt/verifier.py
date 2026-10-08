from __future__ import annotations

import re

import bcrypt

from core.exceptions import InvalidHashError
from modules.passwords.bcrypt.config import (
    SUPPORTED_PREFIXES,
)
from modules.passwords.bcrypt.hasher import (
    BcryptHasher,
)


BCRYPT_PATTERN = re.compile(
    r"^\$2[aby]\$"
    r"(0[4-9]|[12][0-9]|3[01])\$"
    r"[./A-Za-z0-9]{53}$"
)


class BcryptVerifier:
    """
    Normalização, validação e verificação bcrypt.
    """

    @classmethod
    def prepare_hash(
        cls,
        hash_value: str,
    ) -> str:
        normalized = (
            cls.normalize_hash(
                hash_value
            )
        )

        cls.validate_hash(
            normalized
        )

        return normalized

    @staticmethod
    def normalize_hash(
        hash_value: str,
    ) -> str:
        if not isinstance(
            hash_value,
            str,
        ):
            raise InvalidHashError(
                "O hash bcrypt precisa ser texto."
            )

        normalized = (
            hash_value.strip()
        )

        if not normalized:
            raise InvalidHashError(
                "O hash bcrypt está vazio."
            )

        # Compatibilidade com o formato existente
        # no banco usado durante o laboratório:
        #
        # $12$...
        #
        # em vez do formato completo:
        #
        # $2b$12$...
        if normalized.startswith(
            "$12$"
        ):
            normalized = (
                f"$2b{normalized}"
            )

        return normalized

    @staticmethod
    def validate_hash(
        hash_value: str,
    ) -> None:
        if not hash_value.startswith(
            SUPPORTED_PREFIXES
        ):
            raise InvalidHashError(
                "Prefixo bcrypt não reconhecido."
            )

        if len(hash_value) != 60:
            raise InvalidHashError(
                "Um hash bcrypt completo deve possuir "
                "60 caracteres."
            )

        if not BCRYPT_PATTERN.fullmatch(
            hash_value
        ):
            raise InvalidHashError(
                "Formato bcrypt inválido."
            )

    @staticmethod
    def verify_candidate(
        candidate: str,
        prepared_hash: str,
    ) -> bool:
        try:
            return bcrypt.checkpw(
                BcryptHasher.password_to_bytes(
                    candidate
                ),
                prepared_hash.encode(
                    "utf-8"
                ),
            )

        except (
            ValueError,
            TypeError,
        ):
            return False