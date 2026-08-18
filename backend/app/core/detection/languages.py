"""Source-language / file-type detection by extension and filename."""
from __future__ import annotations

import os
from typing import Optional

# Extension -> canonical language / file-type name
_EXT_TO_LANG = {
    ".py": "Python",
    ".pyi": "Python",
    ".java": "Java",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".rb": "Ruby",
    ".rake": "Ruby",
    # Infrastructure-as-code / CI / config
    ".tf": "Terraform",
    ".tfvars": "Terraform",
    ".tpl": "Helm",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".ini": "INI",
    ".cfg": "INI",
}

# Bare filename (lowercased) -> language / file-type
_FILENAME_TO_LANG = {
    "dockerfile": "Dockerfile",
    "containerfile": "Dockerfile",
    "makefile": "Config",
    "gemfile": "Ruby",
    "rakefile": "Ruby",
    "jenkinsfile": "Jenkins",
    "vagrantfile": "Ruby",
}

# Extensions scanned as generic "Config" (certs, server configs, secrets files)
_CONFIG_EXTS = {
    ".pem", ".crt", ".cer", ".key", ".conf", ".cnf",
    ".toml", ".properties", ".env",
}

# Languages considered "programming languages" for the reference list.
SUPPORTED_LANGUAGES = sorted(
    {
        "Python", "Java", "C", "C++", "Go", "Rust", "JavaScript", "TypeScript",
        "PHP", "C#", "Swift", "Kotlin", "Ruby",
    }
)

# File-type categories advertised as scannable (for the UI / docs).
SUPPORTED_FILETYPES = sorted(set(_EXT_TO_LANG.values()) | {"Config", "Jenkins"})

# Directories that never contain first-party source worth scanning.
IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", "target", "bin", "obj", ".idea",
    ".vscode", "vendor", ".mypy_cache", ".pytest_cache", "site-packages",
}

# Skip anything larger than this (bytes) - likely generated/binary.
MAX_FILE_BYTES = 2_000_000


def detect_language(path: str) -> Optional[str]:
    """Return the canonical language/file-type for a path, or None if unscannable."""
    base = os.path.basename(path).lower()
    if base in _FILENAME_TO_LANG:
        return _FILENAME_TO_LANG[base]
    # Dockerfile variants like "Dockerfile.prod"
    if base.startswith("dockerfile"):
        return "Dockerfile"
    _, ext = os.path.splitext(base)
    if ext in _EXT_TO_LANG:
        return _EXT_TO_LANG[ext]
    if ext in _CONFIG_EXTS:
        return "Config"
    return None


def is_scannable(path: str) -> bool:
    return detect_language(path) is not None
