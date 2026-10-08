from pathlib import Path

ROOT = Path(".").resolve()
OUTPUT_FILE = ROOT / "estrutura-atual.txt"

IGNORE_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "staticfiles",
    "media",
    "logs",
    "tmp",
    "dist",
    "build",
    ".next",
    ".gradle",
}

IGNORE_FILES = {
    ".DS_Store",
    "db.sqlite3",
    "estrutura-django-atual.txt",
    "arquivos-api-colecao.txt",
}

def should_ignore(path: Path) -> bool:
    name = path.name

    if name in IGNORE_FILES:
        return True

    if path.is_dir() and name in IGNORE_DIRS:
        return True

    parts = set(path.parts)

    return bool(parts.intersection(IGNORE_DIRS))

def build_tree(directory: Path, prefix: str = "") -> list[str]:
    lines = []

    items = [
        item for item in directory.iterdir()
        if not should_ignore(item)
    ]

    items.sort(key=lambda item: (not item.is_dir(), item.name.lower()))

    for index, item in enumerate(items):
        is_last = index == len(items) - 1
        connector = "└── " if is_last else "├── "

        lines.append(f"{prefix}{connector}{item.name}")

        if item.is_dir():
            extension = "    " if is_last else "│   "
            lines.extend(build_tree(item, prefix + extension))

    return lines

project_name = ROOT.name
lines = [project_name]
lines.extend(build_tree(ROOT))

OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")

print(f"Arquivo gerado: {OUTPUT_FILE}")
