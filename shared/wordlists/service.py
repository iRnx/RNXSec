from __future__ import annotations

from shared.wordlists.registry import WordlistRegistry
from shared.wordlists.source import WordlistSource


class WordlistService:
    """
    Operações de alto nível sobre wordlists.
    """

    @classmethod
    def password_sources(
        cls,
        only_available: bool = True,
    ) -> tuple[WordlistSource, ...]:
        sources = (
            WordlistRegistry.password_sources()
        )

        if not only_available:
            return sources

        return tuple(
            source
            for source in sources
            if source.exists
        )

    @classmethod
    def password_source_by_index(
        cls,
        index: int,
    ) -> WordlistSource:
        sources = cls.password_sources()

        if index < 1 or index > len(sources):
            raise ValueError(
                "Índice de wordlist inválido."
            )

        return sources[index - 1]