from __future__ import annotations


class SecurityLabError(Exception):
    """Erro base da aplicação."""


class ConfigurationError(SecurityLabError):
    """Erro de configuração da aplicação."""


class ResourceNotFoundError(SecurityLabError):
    """Recurso necessário não foi encontrado."""


class ModuleExecutionError(SecurityLabError):
    """Erro durante a execução de um módulo."""


class InvalidHashError(SecurityLabError):
    """O hash informado é inválido para o algoritmo selecionado."""


class UnknownAlgorithmError(SecurityLabError):
    """O algoritmo solicitado não está registrado."""


class WordlistError(SecurityLabError):
    """Erro relacionado ao carregamento de uma wordlist."""