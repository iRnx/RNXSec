from __future__ import annotations

import base64
import hashlib
import secrets
import string

from modules.passwords.pbkdf2.config import (
    DEFAULT_ITERATIONS,
    DERIVED_KEY_LENGTH,
    DIGEST_NAME,
    ENCODED_ALGORITHM_NAME,
    MAX_ITERATIONS,
    MIN_ITERATIONS,
    SALT_LENGTH,
)


class PBKDF2Hasher:
    """
    Responsável exclusivamente pela geração
    de hashes PBKDF2-HMAC-SHA256.

    O formato utilizado é compatível com o formato
    utilizado pelo PBKDF2PasswordHasher do Django:

        pbkdf2_sha256$iterations$salt$hash
    """

    SALT_ALPHABET = (
        string.ascii_letters
        + string.digits
    )

    @classmethod
    def hash_password(
        cls,
        password: str,
        iterations: int = DEFAULT_ITERATIONS,
        salt: str | None = None,
    ) -> str:
        if password == "":
            raise ValueError(
                "A senha não pode ser vazia."
            )

        cls._validate_iterations(
            iterations
        )

        if salt is None:
            salt = cls.generate_salt()

        cls._validate_salt(
            salt
        )

        derived_key = cls.derive_key(
            password=password,
            salt=salt,
            iterations=iterations,
        )

        encoded_hash = (
            base64.b64encode(
                derived_key
            )
            .decode("ascii")
            .strip()
        )

        return (
            f"{ENCODED_ALGORITHM_NAME}"
            f"${iterations}"
            f"${salt}"
            f"${encoded_hash}"
        )

    @classmethod
    def derive_key(
        cls,
        password: str,
        salt: str,
        iterations: int,
        dklen: int = DERIVED_KEY_LENGTH,
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            DIGEST_NAME,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
            dklen=dklen,
        )

    @classmethod
    def generate_salt(
        cls,
    ) -> str:
        return "".join(
            secrets.choice(
                cls.SALT_ALPHABET
            )
            for _ in range(
                SALT_LENGTH
            )
        )

    @staticmethod
    def _validate_salt(
        salt: str,
    ) -> None:
        if not isinstance(
            salt,
            str,
        ):
            raise TypeError(
                "salt precisa ser texto."
            )

        if not salt:
            raise ValueError(
                "salt não pode ser vazio."
            )

        if "$" in salt:
            raise ValueError(
                "salt não pode conter '$'."
            )

    @staticmethod
    def _validate_iterations(
        iterations: int,
    ) -> None:
        if not isinstance(
            iterations,
            int,
        ):
            raise TypeError(
                "iterations precisa ser inteiro."
            )

        if not (
            MIN_ITERATIONS
            <= iterations
            <= MAX_ITERATIONS
        ):
            raise ValueError(
                "iterations precisa estar entre "
                f"{MIN_ITERATIONS:,} e "
                f"{MAX_ITERATIONS:,}."
            )