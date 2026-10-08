from __future__ import annotations

import time
from collections.abc import Callable, Sequence

from config.settings import DEFAULT_PROGRESS_INTERVAL
from modules.passwords.base import PasswordAlgorithm
from modules.passwords.result import (
    CrackProgress,
    CrackResult,
)
from modules.passwords.target import PasswordHashTarget
from shared.wordlists.source import WordlistSource


ProgressCallback = Callable[
    [CrackProgress],
    None,
]


class PasswordCracker:
    """
    Motor genérico de teste de candidatos.

    Ele não conhece bcrypt, PBKDF2, Argon2 etc.

    A implementação criptográfica é fornecida
    através de PasswordAlgorithm.
    """

    def __init__(
        self,
        progress_interval: int = DEFAULT_PROGRESS_INTERVAL,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        if progress_interval < 0:
            raise ValueError(
                "progress_interval não pode ser negativo."
            )

        self.progress_interval = (
            progress_interval
        )

        self.progress_callback = (
            progress_callback
        )

    def crack(
        self,
        target: PasswordHashTarget,
        algorithm: PasswordAlgorithm,
        sources: Sequence[WordlistSource],
    ) -> CrackResult:
        """
        Percorre todas as fontes até:

        - encontrar o candidato; ou
        - esgotar todas as wordlists.
        """

        prepared_hash = (
            algorithm.prepare_hash(
                target.hash_value
            )
        )

        attempts = 0

        started_at = (
            time.perf_counter()
        )

        for source in sources:
            files = source.files()

            for file_path in files:
                for candidate in (
                    source.iter_candidates(
                        file_path
                    )
                ):
                    attempts += 1

                    if algorithm.verify_candidate(
                        candidate,
                        prepared_hash,
                    ):
                        elapsed = (
                            time.perf_counter()
                            - started_at
                        )

                        return CrackResult(
                            target_name=target.name,
                            algorithm=algorithm.name,
                            found=True,
                            password=candidate,
                            source_name=source.name,
                            file=file_path,
                            attempts=attempts,
                            elapsed_seconds=elapsed,
                            attempts_per_second=(
                                self._speed(
                                    attempts,
                                    elapsed,
                                )
                            ),
                        )

                    self._notify_progress(
                        target=target,
                        source=source,
                        file_path=file_path,
                        attempts=attempts,
                        started_at=started_at,
                    )

        elapsed = (
            time.perf_counter()
            - started_at
        )

        return CrackResult(
            target_name=target.name,
            algorithm=algorithm.name,
            found=False,
            password=None,
            source_name=None,
            file=None,
            attempts=attempts,
            elapsed_seconds=elapsed,
            attempts_per_second=(
                self._speed(
                    attempts,
                    elapsed,
                )
            ),
        )

    def _notify_progress(
        self,
        target: PasswordHashTarget,
        source: WordlistSource,
        file_path,
        attempts: int,
        started_at: float,
    ) -> None:
        if self.progress_callback is None:
            return

        if self.progress_interval <= 0:
            return

        if (
            attempts
            % self.progress_interval
            != 0
        ):
            return

        elapsed = (
            time.perf_counter()
            - started_at
        )

        self.progress_callback(
            CrackProgress(
                target_name=target.name,
                source_name=source.name,
                file=file_path,
                attempts=attempts,
                elapsed_seconds=elapsed,
                attempts_per_second=(
                    self._speed(
                        attempts,
                        elapsed,
                    )
                ),
            )
        )

    @staticmethod
    def _speed(
        attempts: int,
        elapsed: float,
    ) -> float:
        if elapsed <= 0:
            return 0.0

        return attempts / elapsed