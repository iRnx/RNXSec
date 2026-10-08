from __future__ import annotations

from core.exceptions import (
    UnknownAlgorithmError,
)
from modules.passwords.base import (
    PasswordAlgorithm,
)
from modules.passwords.bcrypt.service import (
    BcryptService,
)
from modules.passwords.pbkdf2.service import (
    PBKDF2Service,
)


class PasswordAlgorithmRegistry:
    """
    Registro dos algoritmos funcionalmente disponíveis.

    Um módulo só deve ser registrado depois que sua
    implementação estiver concluída.
    """

    _algorithms: dict[
        str,
        PasswordAlgorithm,
    ] = {
        "bcrypt": BcryptService(),
        "pbkdf2": PBKDF2Service(),
    }

    @classmethod
    def get(
        cls,
        name: str,
    ) -> PasswordAlgorithm:
        key = (
            name
            .strip()
            .lower()
        )

        algorithm = (
            cls._algorithms.get(
                key
            )
        )

        if algorithm is None:
            raise UnknownAlgorithmError(
                "Algoritmo não registrado: "
                f"{name}"
            )

        return algorithm

    @classmethod
    def names(
        cls,
    ) -> tuple[str, ...]:
        return tuple(
            cls._algorithms.keys()
        )