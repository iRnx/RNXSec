from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from config.settings import (
    DEFAULT_ENCODING,
    WORDLIST_SUPPORTED_EXTENSIONS,
)


@dataclass(frozen=True, slots=True)
class WordlistSource:
    """
    Representa uma fonte de candidatos.

    Uma fonte pode apontar para:

    - um único arquivo;
    - um diretório;
    - uma árvore inteira de diretórios.
    """

    name: str
    path: Path
    recursive: bool = True

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def files(self) -> tuple[Path, ...]:
        """
        Retorna os arquivos compatíveis da fonte.

        Não lê o conteúdo dos arquivos.
        """

        if not self.path.exists():
            return ()

        if self.path.is_file():
            if self._is_supported_file(
                self.path
            ):
                return (self.path,)

            return ()

        iterator = (
            self.path.rglob("*")
            if self.recursive
            else self.path.glob("*")
        )

        files = [
            path
            for path in iterator
            if (
                path.is_file()
                and self._is_supported_file(path)
            )
        ]

        return tuple(
            sorted(
                files,
                key=lambda item: str(item).lower(),
            )
        )

    def iter_candidates(
        self,
        file_path: Path,
    ) -> Iterator[str]:
        """
        Lê uma wordlist em streaming.

        O arquivo inteiro nunca é carregado na memória.
        """

        with file_path.open(
            "r",
            encoding=DEFAULT_ENCODING,
            errors="ignore",
        ) as stream:
            for line in stream:
                # Remove SOMENTE quebra de linha.
                #
                # Não usamos strip(), pois espaços podem fazer
                # parte de uma senha válida.
                candidate = line.rstrip(
                    "\r\n"
                )

                if not candidate:
                    continue

                yield candidate

    @staticmethod
    def _is_supported_file(
        path: Path,
    ) -> bool:
        return (
            path.suffix.lower()
            in WORDLIST_SUPPORTED_EXTENSIONS
        )