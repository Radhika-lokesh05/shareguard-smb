"""
shareguard.entropy – Shannon entropy helpers for file-rename detection.

Ransomware typically renames files to random-looking extensions (e.g. ``.locked``,
``.crypt``, or random hex strings). High Shannon entropy in the distribution of
new extensions is a strong signal.

All functions are pure and have no side effects.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

__all__ = [
    "shannon_entropy",
    "string_entropy",
    "extension_entropy",
    "SimulatedEntropyProvider",
    "FileEntropyProvider",
]


def shannon_entropy(probabilities: list[float]) -> float:
    """Compute the Shannon entropy of a probability distribution.

    Args:
        probabilities: List of probability values (must sum to ~1.0).
            Zero values are silently skipped.

    Returns:
        Entropy in bits (base-2 logarithm). Returns 0.0 if empty.
    """
    entropy = 0.0
    for p in probabilities:
        if p > 0.0:
            entropy -= p * math.log2(p)
    return max(0.0, entropy)


def string_entropy(text: str) -> float:
    """Estimate the Shannon entropy of a string by character frequency.

    Useful for evaluating whether a file extension looks random.

    Args:
        text: Input string (e.g. a file extension like ``"crypt"``).

    Returns:
        Entropy in bits. Empty strings return 0.0.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    probabilities = [count / length for count in counts.values()]
    return shannon_entropy(probabilities)


def extension_entropy(extensions: list[str]) -> float:
    """Compute the entropy across a collection of file extensions.

    Args:
        extensions: List of file extensions (e.g. ``[".crypt", ".locked", …]``).
            Should already be lower-cased.

    Returns:
        Shannon entropy of the extension distribution in bits.
        Returns 0.0 for an empty list.
    """
    if not extensions:
        return 0.0

    total = len(extensions)
    counts = Counter(extensions)
    probabilities = [count / total for count in counts.values()]
    return shannon_entropy(probabilities)


class SimulatedEntropyProvider:
    """Entropy provider for simulated environments.

    Calculates or estimates file content entropy based on file extension,
    simulated operation flags, or path hints without requiring physical files on disk.
    """

    def __init__(self, default_suspicious_entropy: float = 7.9) -> None:
        self.default_suspicious_entropy = default_suspicious_entropy

    def get_entropy(self, path: str, flags: str = "", is_attack: bool = False) -> float:
        """Return Shannon entropy score (0.0 - 8.0) for a given path and operation."""
        norm_path = path.replace("\\", "/").lower()
        if is_attack or ".locked" in norm_path or ".crypt" in norm_path or "0x42" in flags:
            return self.default_suspicious_entropy

        # Common file extensions
        if any(norm_path.endswith(ext) for ext in [".zip", ".gz", ".tar", ".7z", ".mp4", ".iso"]):
            return 7.5
        if any(norm_path.endswith(ext) for ext in [".docx", ".xlsx", ".pptx", ".pdf"]):
            return 5.8
        if any(norm_path.endswith(ext) for ext in [".txt", ".csv", ".py", ".js", ".json", ".log"]):
            return 3.8
        return 4.5


class FileEntropyProvider:
    """Entropy provider that samples physical file content from disk.

    Reads up to sample_size_bytes from the file at path (absolute path)
    and computes the Shannon byte entropy (0.0 to 8.0 bits).
    Falls back to SimulatedEntropyProvider if the file does not exist,
    is unreadable, or when in simulation mode.
    """

    def __init__(
        self,
        fallback: SimulatedEntropyProvider | None = None,
        sample_size_bytes: int = 65536,
    ) -> None:
        self.fallback = fallback or SimulatedEntropyProvider()
        self.sample_size_bytes = sample_size_bytes

    def get_entropy(self, path: str, flags: str = "", is_attack: bool = False) -> float:
        """Sample byte entropy from disk if file exists; otherwise use fallback provider."""
        p = Path(path)
        if p.is_file():
            try:
                with p.open("rb") as f:
                    data = f.read(self.sample_size_bytes)
                if data:
                    total = len(data)
                    counts = Counter(data)
                    probs = [count / total for count in counts.values()]
                    return shannon_entropy(probs)
            except (OSError, PermissionError):
                pass
        return self.fallback.get_entropy(path, flags=flags, is_attack=is_attack)


