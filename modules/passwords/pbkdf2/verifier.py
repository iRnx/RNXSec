from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass

from core.exceptions import InvalidHashError
from modules.passwords.pbkdf2.config import (
    DIGEST_NAME,
    ENCODED_ALGORITHM_NAME,
    MAX_ITERATIONS,
    MIN_ITERATIONS,
)


@dataclass(
    frozen=True,
    slots=True,
)
class PreparedPBKDF2Hash:
    algorithm: str

    digest_name: str

    iterations: int

    salt: bytes

    salt_display: str

    expected_hash: bytes

    format_name: str


class PBKDF2Verifier:
    """
    Parsing, validação e verificação de hashes PBKDF2.

    Atualmente suporta:

    1. Formato Django:
       pbkdf2_sha256$iterations$salt$hash

    2. Formato Devglan / Java-style:
       PBKDF2$PBKDF2WithHmacSHA256$iterations$salt_base64$hash_base64
    """

    @classmethod
    def prepare_hash(
        cls,
        hash_value: str,
    ) -> PreparedPBKDF2Hash:
        normalized = (
            cls.normalize_hash(
                hash_value
            )
        )

        if normalized.startswith(
            f"{ENCODED_ALGORITHM_NAME}$"
        ):
            return (
                cls._prepare_django_format(
                    normalized
                )
            )

        if normalized.startswith(
            "PBKDF2$"
        ):
            return (
                cls._prepare_devglan_format(
                    normalized
                )
            )

        raise InvalidHashError(
            "Formato PBKDF2 não reconhecido."
        )

    @staticmethod
    def normalize_hash(
        hash_value: str,
    ) -> str:
        if not isinstance(
            hash_value,
            str,
        ):
            raise InvalidHashError(
                "O hash PBKDF2 precisa ser texto."
            )

        normalized = (
            hash_value.strip()
        )

        if not normalized:
            raise InvalidHashError(
                "O hash PBKDF2 está vazio."
            )

        return normalized

    @classmethod
    def _prepare_django_format(
        cls,
        hash_value: str,
    ) -> PreparedPBKDF2Hash:
        parts = hash_value.split(
            "$",
            3,
        )

        if len(parts) != 4:
            raise InvalidHashError(
                "Formato Django PBKDF2 inválido."
            )

        (
            algorithm,
            iterations_raw,
            salt_text,
            encoded_hash,
        ) = parts

        if (
            algorithm
            != ENCODED_ALGORITHM_NAME
        ):
            raise InvalidHashError(
                "Algoritmo PBKDF2 não suportado: "
                f"{algorithm!r}"
            )

        iterations = (
            cls._parse_iterations(
                iterations_raw
            )
        )

        if not salt_text:
            raise InvalidHashError(
                "O salt PBKDF2 está vazio."
            )

        expected_hash = (
            cls._decode_base64(
                encoded_hash,
                "digest PBKDF2",
            )
        )

        return PreparedPBKDF2Hash(
            algorithm=algorithm,
            digest_name=DIGEST_NAME,
            iterations=iterations,
            salt=salt_text.encode(
                "utf-8"
            ),
            salt_display=salt_text,
            expected_hash=expected_hash,
            format_name="django",
        )

    @classmethod
    def _prepare_devglan_format(
        cls,
        hash_value: str,
    ) -> PreparedPBKDF2Hash:
        parts = hash_value.split(
            "$"
        )

        if len(parts) != 5:
            raise InvalidHashError(
                "Formato PBKDF2 externo inválido. "
                "Esperado: "
                "PBKDF2$PBKDF2WithHmacSHA256$"
                "iterations$salt_base64$hash_base64"
            )

        (
            family,
            algorithm,
            iterations_raw,
            encoded_salt,
            encoded_hash,
        ) = parts

        if family.upper() != "PBKDF2":
            raise InvalidHashError(
                "Família PBKDF2 inválida."
            )

        normalized_algorithm = (
            algorithm.lower()
        )

        if normalized_algorithm not in {
            "pbkdf2withhmacsha256",
            "pbkdf2withhmacsha-256",
        }:
            raise InvalidHashError(
                "Algoritmo PBKDF2 não suportado: "
                f"{algorithm!r}. "
                "Atualmente suportamos "
                "PBKDF2WithHmacSHA256."
            )

        iterations = (
            cls._parse_iterations(
                iterations_raw
            )
        )

        salt = cls._decode_base64(
            encoded_salt,
            "salt PBKDF2",
        )

        expected_hash = (
            cls._decode_base64(
                encoded_hash,
                "digest PBKDF2",
            )
        )

        return PreparedPBKDF2Hash(
            algorithm=algorithm,
            digest_name="sha256",
            iterations=iterations,
            salt=salt,
            salt_display=salt.hex(),
            expected_hash=expected_hash,
            format_name="external-base64",
        )

    @staticmethod
    def verify_candidate(
        candidate: str,
        prepared_hash: PreparedPBKDF2Hash,
    ) -> bool:
        candidate_hash = hashlib.pbkdf2_hmac(
            prepared_hash.digest_name,
            candidate.encode(
                "utf-8"
            ),
            prepared_hash.salt,
            prepared_hash.iterations,
            dklen=len(
                prepared_hash.expected_hash
            ),
        )

        return hmac.compare_digest(
            candidate_hash,
            prepared_hash.expected_hash,
        )

    @staticmethod
    def _parse_iterations(
        value: str,
    ) -> int:
        try:
            iterations = int(
                value
            )

        except ValueError as exc:
            raise InvalidHashError(
                "O número de iterações "
                "PBKDF2 é inválido."
            ) from exc

        if not (
            MIN_ITERATIONS
            <= iterations
            <= MAX_ITERATIONS
        ):
            raise InvalidHashError(
                "Número de iterações PBKDF2 "
                "fora do intervalo aceito."
            )

        return iterations

    @staticmethod
    def _decode_base64(
        value: str,
        field_name: str,
    ) -> bytes:
        if not value:
            raise InvalidHashError(
                f"{field_name} está vazio."
            )

        try:
            decoded = (
                base64.b64decode(
                    value,
                    validate=True,
                )
            )

        except (
            binascii.Error,
            ValueError,
        ) as exc:
            raise InvalidHashError(
                f"{field_name} não possui "
                "Base64 válido."
            ) from exc

        if not decoded:
            raise InvalidHashError(
                f"{field_name} decodificado "
                "está vazio."
            )

        return decoded