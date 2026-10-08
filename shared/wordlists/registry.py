from __future__ import annotations

from config.paths import WORDLISTS_DIR
from shared.wordlists.source import WordlistSource


class WordlistRegistry:
    """
    Registro central das coleções disponíveis.

    O registry conhece os caminhos físicos.
    Os módulos não precisam conhecê-los.
    """

    _PASSWORD_SOURCES = (
        WordlistSource(
            name="RockYou",
            path=(
                WORDLISTS_DIR
                / "rockyou"
                / "rockyou.txt"
            ),
            recursive=False,
        ),

        WordlistSource(
            name="Cybbaris - Passwords",
            path=(
                WORDLISTS_DIR
                / "cybbaris_wordlists"
                / "passwords"
            ),
        ),

        WordlistSource(
            name="SecLists - Passwords",
            path=(
                WORDLISTS_DIR
                / "SecLists"
                / "Passwords"
            ),
        ),

        WordlistSource(
            name="Wordlists - Common Passwords",
            path=(
                WORDLISTS_DIR
                / "wordlists"
                / "common-passwords"
            ),
        ),

        WordlistSource(
            name="Wordlists - Password Dictionaries",
            path=(
                WORDLISTS_DIR
                / "wordlists"
                / "password-dictionaries"
            ),
        ),

        WordlistSource(
            name="Wordlists - Leaked Databases",
            path=(
                WORDLISTS_DIR
                / "wordlists"
                / "leaked-databases"
            ),
        ),

        WordlistSource(
            name="Wordlists - Keyboard Walks",
            path=(
                WORDLISTS_DIR
                / "wordlists"
                / "keyboard-walks"
            ),
        ),
    )

    @classmethod
    def password_sources(
        cls,
    ) -> tuple[WordlistSource, ...]:
        return cls._PASSWORD_SOURCES