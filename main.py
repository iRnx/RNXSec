from __future__ import annotations

from modules.passwords.bcrypt.runner import (
    BcryptRunner,
)
from modules.passwords.pbkdf2.runner import (
    PBKDF2Runner,
)


def print_header(
    title: str,
) -> None:
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def password_menu() -> None:
    while True:
        print_header(
            "PASSWORD / HASH"
        )

        print()
        print(
            "1 - bcrypt"
        )
        print(
            "2 - PBKDF2"
        )

        print()
        print(
            "0 - Voltar"
        )
        print()

        option = input(
            "Escolha: "
        ).strip()

        if option == "1":
            BcryptRunner().run()

        elif option == "2":
            PBKDF2Runner().run()

        elif option == "0":
            return

        else:
            print()
            print(
                "Opção inválida."
            )


def main() -> None:
    while True:
        print_header(
            "SECURITY LAB"
        )

        print()
        print(
            "1 - Password / Hash"
        )

        print(
            "0 - Sair"
        )

        print()

        option = input(
            "Escolha: "
        ).strip()

        if option == "1":
            password_menu()

        elif option == "0":
            print()
            print(
                "Finalizado."
            )
            return

        else:
            print()
            print(
                "Opção inválida."
            )


if __name__ == "__main__":
    main()