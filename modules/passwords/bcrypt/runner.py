from __future__ import annotations

from core.exceptions import InvalidHashError
from modules.passwords.bcrypt.config import (
    DEFAULT_ROUNDS,
)
from modules.passwords.bcrypt.service import (
    BcryptService,
)
from modules.passwords.cracker import (
    PasswordCracker,
)
from modules.passwords.result import (
    CrackProgress,
    CrackResult,
)
from modules.passwords.target import (
    PasswordHashTarget,
)
from shared.wordlists.service import (
    WordlistService,
)
from shared.wordlists.source import (
    WordlistSource,
)


class BcryptRunner:
    def __init__(self) -> None:
        self.service = (
            BcryptService()
        )

    def run(self) -> None:
        while True:
            self._header(
                "BCRYPT"
            )

            print()
            print(
                "1 - Testar hash(es) com wordlists"
            )
            print(
                "2 - Gerar hash e testar com wordlists"
            )
            print(
                "3 - Verificar senha específica"
            )
            print(
                "4 - Gerar hash bcrypt"
            )
            print(
                "0 - Voltar"
            )
            print()

            option = input(
                "Escolha: "
            ).strip()

            if option == "1":
                self._crack_existing_hashes()

            elif option == "2":
                self._generate_and_crack()

            elif option == "3":
                self._verify_specific_password()

            elif option == "4":
                self._generate_hash()

            elif option == "0":
                return

            else:
                print()
                print(
                    "Opção inválida."
                )

    def _crack_existing_hashes(
        self,
    ) -> None:
        self._header(
            "TESTAR HASHES BCRYPT"
        )

        count = (
            self._read_positive_int(
                "Quantidade de hashes: "
            )
        )

        targets: list[
            PasswordHashTarget
        ] = []

        for index in range(
            1,
            count + 1,
        ):
            print()

            hash_value = input(
                f"Hash {index}: "
            ).strip()

            targets.append(
                PasswordHashTarget(
                    name=(
                        f"Hash {index:02d}"
                    ),
                    algorithm="bcrypt",
                    hash_value=hash_value,
                )
            )

        sources = (
            self._select_sources()
        )

        self._run_targets(
            targets=targets,
            sources=sources,
        )

    def _generate_and_crack(
        self,
    ) -> None:
        self._header(
            "GERAR E TESTAR BCRYPT"
        )

        password = input(
            "Texto/senha: "
        )

        rounds = (
            self._read_rounds()
        )

        password_hash = (
            self.service.hash_password(
                password=password,
                rounds=rounds,
            )
        )

        print()
        print(
            "Hash gerado:"
        )
        print(
            password_hash
        )

        target = PasswordHashTarget(
            name="Hash gerado",
            algorithm="bcrypt",
            hash_value=password_hash,
        )

        sources = (
            self._select_sources()
        )

        self._run_targets(
            targets=[target],
            sources=sources,
        )

    def _verify_specific_password(
        self,
    ) -> None:
        self._header(
            "VERIFICAR SENHA"
        )

        hash_value = input(
            "Hash bcrypt: "
        ).strip()

        password = input(
            "Senha candidata: "
        )

        try:
            matches = (
                self.service.verify_password(
                    password=password,
                    hash_value=hash_value,
                )
            )

        except InvalidHashError as exc:
            print()
            print(
                f"Hash inválido: {exc}"
            )
            return

        print()

        if matches:
            print(
                "RESULTADO: CORRESPONDE"
            )
        else:
            print(
                "RESULTADO: NÃO CORRESPONDE"
            )

    def _generate_hash(
        self,
    ) -> None:
        self._header(
            "GERAR HASH BCRYPT"
        )

        password = input(
            "Texto/senha: "
        )

        rounds = (
            self._read_rounds()
        )

        password_hash = (
            self.service.hash_password(
                password=password,
                rounds=rounds,
            )
        )

        print()
        print(
            "Hash:"
        )
        print(
            password_hash
        )

    def _run_targets(
        self,
        targets: list[PasswordHashTarget],
        sources: tuple[WordlistSource, ...],
    ) -> None:
        cracker = PasswordCracker(
            progress_interval=100,
            progress_callback=(
                self._show_progress
            ),
        )

        results: list[
            CrackResult
        ] = []

        try:
            for target in targets:
                self._header(
                    f"ALVO: {target.name}"
                )

                try:
                    normalized = (
                        self.service.prepare_hash(
                            target.hash_value
                        )
                    )

                except InvalidHashError as exc:
                    print()
                    print(
                        f"Hash inválido: {exc}"
                    )
                    continue

                print()
                print(
                    "Hash original:"
                )
                print(
                    target.hash_value
                )

                if (
                    normalized
                    != target.hash_value
                ):
                    print()
                    print(
                        "Hash normalizado:"
                    )
                    print(
                        normalized
                    )

                print()
                print(
                    f"Fontes selecionadas: "
                    f"{len(sources)}"
                )

                print()

                result = cracker.crack(
                    target=target,
                    algorithm=self.service,
                    sources=sources,
                )

                results.append(
                    result
                )

                self._show_result(
                    result
                )

        except KeyboardInterrupt:
            print()
            print()
            print(
                "Execução interrompida com Ctrl+C."
            )

            return

        self._show_summary(
            results
        )

    @staticmethod
    def _show_progress(
        progress: CrackProgress,
    ) -> None:
        print(
            "\r"
            f"{progress.source_name} | "
            f"{progress.file.name} | "
            f"{progress.attempts:,} tentativas | "
            f"{progress.attempts_per_second:.2f} senhas/s | "
            f"{progress.elapsed_seconds:.1f}s",
            end="",
            flush=True,
        )

    @classmethod
    def _show_result(
        cls,
        result: CrackResult,
    ) -> None:
        print()
        print()

        if not result.found:
            print(
                "Senha não encontrada."
            )

            print(
                f"Tentativas: "
                f"{result.attempts:,}"
            )

            print(
                f"Tempo: "
                f"{result.elapsed_seconds:.2f}s"
            )

            return

        cls._header(
            "SENHA ENCONTRADA"
        )

        print()
        print(
            f"Senha:      "
            f"{result.password}"
        )

        print(
            f"Fonte:      "
            f"{result.source_name}"
        )

        print(
            f"Arquivo:    "
            f"{result.file}"
        )

        print(
            f"Tentativas: "
            f"{result.attempts:,}"
        )

        print(
            f"Tempo:      "
            f"{result.elapsed_seconds:.2f}s"
        )

        print(
            f"Velocidade: "
            f"{result.attempts_per_second:.2f} "
            f"senhas/s"
        )

    @classmethod
    def _show_summary(
        cls,
        results: list[CrackResult],
    ) -> None:
        if not results:
            return

        cls._header(
            "RESUMO"
        )

        for result in results:
            print()

            if result.found:
                print(
                    f"{result.target_name}: "
                    f"ENCONTRADO"
                )

                print(
                    f"Senha: {result.password}"
                )
            else:
                print(
                    f"{result.target_name}: "
                    f"NÃO ENCONTRADO"
                )

    @staticmethod
    def _select_sources(
    ) -> tuple[WordlistSource, ...]:
        sources = (
            WordlistService
            .password_sources()
        )

        if not sources:
            raise RuntimeError(
                "Nenhuma wordlist disponível."
            )

        print()
        print(
            "Wordlists disponíveis:"
        )
        print()

        for index, source in enumerate(
            sources,
            start=1,
        ):
            print(
                f"{index} - {source.name}"
            )

        print()
        print(
            "A - Todas"
        )

        print()

        selection = input(
            "Escolha [A]: "
        ).strip()

        if not selection:
            return sources

        if selection.lower() == "a":
            return sources

        indexes: list[int] = []

        try:
            for item in selection.split(
                ","
            ):
                indexes.append(
                    int(
                        item.strip()
                    )
                )

        except ValueError:
            print()
            print(
                "Seleção inválida. "
                "Todas serão utilizadas."
            )

            return sources

        selected: list[
            WordlistSource
        ] = []

        for index in indexes:
            if (
                1
                <= index
                <= len(sources)
            ):
                selected.append(
                    sources[index - 1]
                )

        if not selected:
            return sources

        return tuple(
            selected
        )

    @staticmethod
    def _read_rounds() -> int:
        raw = input(
            f"Rounds [{DEFAULT_ROUNDS}]: "
        ).strip()

        if not raw:
            return DEFAULT_ROUNDS

        return int(
            raw
        )

    @staticmethod
    def _read_positive_int(
        message: str,
    ) -> int:
        while True:
            raw = input(
                message
            ).strip()

            try:
                value = int(
                    raw
                )

            except ValueError:
                print(
                    "Digite um número inteiro."
                )
                continue

            if value <= 0:
                print(
                    "O valor precisa ser maior que zero."
                )
                continue

            return value

    @staticmethod
    def _header(
        title: str,
    ) -> None:
        print()
        print("=" * 80)
        print(title)
        print("=" * 80)