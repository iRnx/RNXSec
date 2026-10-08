from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class PasswordAlgorithm(ABC):
    """
    Contrato de qualquer algoritmo usado pelo motor
    de verificação de passwords.
    """

    name: str

    @abstractmethod
    def prepare_hash(
        self,
        hash_value: str,
    ) -> Any:
        """
        Valida e prepara o hash uma única vez.

        O retorno será reutilizado durante todas
        as tentativas da wordlist.
        """

        raise NotImplementedError

    @abstractmethod
    def verify_candidate(
        self,
        candidate: str,
        prepared_hash: Any,
    ) -> bool:
        """
        Verifica um candidato contra um hash já preparado.
        """

        raise NotImplementedError