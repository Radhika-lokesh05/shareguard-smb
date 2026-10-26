"""
lab/fake_ransomware.py – Lab-only file encryption simulator.

⚠️  THIS IS A SIMULATION TOOL ONLY.  ⚠️
It must NEVER be imported or called from production code.

Uses the ``cryptography`` library (Fernet / AES-128-CBC + HMAC-SHA256) to
produce ciphertext with realistic high entropy.  A fresh key is generated per
run and saved next to the manifest so the ``--restore`` option can decrypt
everything and verify SHA-256 hashes against the manifest.

SAFETY – the script refuses to run unless ALL of the following are true:

1. Target contains ``.shareguard_lab_marker`` (or legacy ``SHAREGUARD_LAB_MARKER``).
2. Target is not a filesystem root (``/``, ``C:\\``, etc.).
3. Target is not the user's home directory, and does not *contain* the home dir.
4. ``manifest.json`` exists in the target (written by ``make_fake_files.py``).
5. ``--i-understand-this-is-a-lab`` is passed (CLI) **or** ``confirmed=True``
   (programmatic API).

Only files listed in ``manifest.json`` are ever touched.

Usage::

    # Create lab environment first:
    python lab/make_fake_files.py --target /mnt/share

    # Run an attack:
    python lab/fake_ransomware.py \\
        --target /mnt/share \\
        --style fast \\
        --i-understand-this-is-a-lab

    # Restore everything:
    python lab/fake_ransomware.py --target /mnt/share --restore

Styles
------
fast        Encrypt whole file, rename to ``<name>.locked``.
slow        Same as fast, with ``--sleep S`` seconds between files.
partial     Encrypt only the first N bytes (``--partial-bytes``) or every
            other 4096-byte block, keeping the original filename.
rename_only Rename to ``<name>.locked`` without changing content; no key written.
copy_delete Write encrypted copy as ``<name>.locked``, delete original.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from lab.safety import (
    KEY_FILENAME,
    MANIFEST_FILENAME,
    MARKER_FILENAME,
    MARKER_LEGACY,
    LabSafetyError,
    check_safety,
    retry_on_windows_busy,
)

CANARY_NAMES: list[str] = [
    "canary_budget.xlsx",
    "canary_payroll.pdf",
    "canary_passwords.txt",
    "canary_contracts.docx",
]

__all__: list[str] = ["encrypt_files", "restore", "simulate_encryption", "LabSafetyError", "CANARY_NAMES"]

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    class InvalidToken(Exception):  # type: ignore[no-redef]
        """Fallback exception when token is invalid."""

    class Fernet:  # type: ignore[no-redef]
        """Fallback pure-Python pseudo-Fernet encryptor for environments without cryptography."""

        def __init__(self, key: bytes) -> None:
            self.key = key

        @staticmethod
        def generate_key() -> bytes:
            import base64
            import os
            return base64.urlsafe_b64encode(os.urandom(32))

        def encrypt(self, data: bytes) -> bytes:
            import base64
            import hashlib
            import os
            iv = os.urandom(16)
            keystream = hashlib.sha256(self.key + iv).digest()
            xored = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(data))
            return base64.urlsafe_b64encode(iv + xored)

        def decrypt(self, token: bytes) -> bytes:
            import base64
            import hashlib
            try:
                raw = base64.urlsafe_b64decode(token)
                if len(raw) < 16:
                    raise InvalidToken("Token too short")
                iv, xored = raw[:16], raw[16:]
                keystream = hashlib.sha256(self.key + iv).digest()
                return bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(xored))
            except Exception as e:
                raise InvalidToken(str(e)) from e

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MARKER_FILENAME = ".shareguard_lab_marker"
MARKER_LEGACY = "SHAREGUARD_LAB_MARKER"
MANIFEST_FILENAME = "manifest.json"
KEY_FILENAME = "manifest.key"
SUMMARY_FILENAME = "run_summary.json"
RANSOM_NOTE_NAME = "README_LAB_NOTE.txt"
RANSOM_NOTE_TEXT = (
    "[LAB ONLY – NOT REAL RANSOMWARE]\n\n"
    "This is a ShareGuard simulation.  Your files have been encrypted with\n"
    "a Fernet key stored at manifest.key in the share root.\n\n"
    "To restore:  python lab/fake_ransomware.py --target <dir> --restore\n"
)

_LOCKED_EXT = ".locked"
_PARTIAL_BLOCK = 4096   # bytes per block for partial style


# ---------------------------------------------------------------------------
# Run summary
# ---------------------------------------------------------------------------


@dataclass
class RunSummary:
    """Captures statistics from one :func:`encrypt_files` run.

    Attributes:
        style: Encryption style used.
        start_utc: ISO-8601 timestamp when the run started.
        end_utc: ISO-8601 timestamp when the run finished.
        files_changed: Number of files actually encrypted / renamed.
        key_file: Path to the saved Fernet key (empty for rename_only).
    """

    style: str
    start_utc: str
    end_utc: str = ""
    files_changed: int = 0
    key_file: str = ""
    errors: list[str] = field(default_factory=list)

    def save(self, target: Path) -> None:
        """Write *self* as ``run_summary.json`` inside *target*."""
        (target / SUMMARY_FILENAME).write_text(
            json.dumps(asdict(self), indent=2), encoding="utf-8"
        )

    def print_report(self) -> None:
        """Print a human-readable summary to stdout."""
        print(
            f"\n[fake_ransomware] Run summary\n"
            f"  Style         : {self.style}\n"
            f"  Start (UTC)   : {self.start_utc}\n"
            f"  End   (UTC)   : {self.end_utc}\n"
            f"  Files changed : {self.files_changed}\n"
            f"  Key file      : {self.key_file or '(none – rename_only)'}\n"
        )
        if self.errors:
            for e in self.errors:
                print(f"  ERROR: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------


def _has_marker(target: Path) -> bool:
    """Return True if either marker file exists in *target*."""
    return (target / MARKER_FILENAME).exists() or (target / MARKER_LEGACY).exists()


def _is_root(target: Path) -> bool:
    """Return True if *target* is a filesystem root (``/``, ``C:\\``, etc.)."""
    return target == target.parent


def _is_home_or_parent_of_home(target: Path) -> bool:
    """Return True if *target* is the home directory or an ancestor of it."""
    try:
        home = Path.home().resolve()
        t = target.resolve()
        # t is home, or home is inside t (t is an ancestor of home)
        return t == home or home.is_relative_to(t)
    except (RuntimeError, ValueError):
        return False


def _check_safety(target: Path, confirmed: bool) -> None:
    """Raise :class:`LabSafetyError` if any safety precondition fails."""
    check_safety(target, confirmed=confirmed, require_manifest=True)


# ---------------------------------------------------------------------------
# Fernet key management
# ---------------------------------------------------------------------------


def _generate_key(target: Path) -> bytes:
    """Generate a fresh Fernet key, save it to ``manifest.key``, and return it.

    Args:
        target: Root directory where the key file is written.

    Returns:
        Raw Fernet key bytes.
    """
    key = Fernet.generate_key()
    (target / KEY_FILENAME).write_bytes(key)
    return key


def _load_key(target: Path) -> bytes:
    """Load the Fernet key from ``manifest.key``.

    Args:
        target: Root directory containing ``manifest.key``.

    Returns:
        Raw Fernet key bytes.

    Raises:
        FileNotFoundError: If ``manifest.key`` does not exist.
    """
    key_path = target / KEY_FILENAME
    if not key_path.exists():
        raise FileNotFoundError(f"Key file '{key_path}' not found.  Cannot restore.")
    return key_path.read_bytes()


# ---------------------------------------------------------------------------
# Manifest loader (local import to keep lab/ self-contained)
# ---------------------------------------------------------------------------


def _load_manifest_entries(target: Path) -> list[dict[str, str]]:
    """Return the list of manifest entries from ``manifest.json``."""
    data = json.loads((target / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    return data["files"]  # type: ignore[return-value]


def _manifest_paths(target: Path) -> set[Path]:
    """Return the set of absolute :class:`Path` objects in the manifest."""
    entries = _load_manifest_entries(target)
    return {(target / e["path"]).resolve() for e in entries}


# ---------------------------------------------------------------------------
# Per-style encryption workers
# ---------------------------------------------------------------------------


def _encrypt_bytes_fernet(plaintext: bytes, fernet: object) -> bytes:
    """Return Fernet-encrypted *plaintext*.

    Args:
        plaintext: Raw bytes to encrypt.
        fernet: A :class:`cryptography.fernet.Fernet` instance.

    Returns:
        Encrypted token bytes (base64url-encoded).
    """
    return fernet.encrypt(plaintext)  # type: ignore[return-value,union-attr]


def _process_file_fast(src: Path, fernet: object, note_dirs: set[Path], ext: str = _LOCKED_EXT) -> bool:
    """Encrypt *src* in place and rename to ``<name><ext>``."""
    try:
        plaintext = retry_on_windows_busy(src.read_bytes)
        token = _encrypt_bytes_fernet(plaintext, fernet)
        dst = src.with_suffix(src.suffix + ext)
        retry_on_windows_busy(src.write_bytes, token)
        retry_on_windows_busy(src.rename, dst)
        note_dirs.add(src.parent)
        return True
    except OSError:
        return False


def _process_file_copy_delete(src: Path, fernet: object, note_dirs: set[Path], ext: str = _LOCKED_EXT) -> bool:
    """Write encrypted copy as ``<name><ext>``, delete original."""
    try:
        plaintext = retry_on_windows_busy(src.read_bytes)
        token = _encrypt_bytes_fernet(plaintext, fernet)
        dst = src.with_suffix(src.suffix + ext)
        retry_on_windows_busy(dst.write_bytes, token)
        retry_on_windows_busy(src.unlink)
        note_dirs.add(src.parent)
        return True
    except OSError:
        return False


def _process_file_partial(
    src: Path, fernet: object, partial_bytes: int, note_dirs: set[Path]
) -> bool:
    """Encrypt first *partial_bytes* (or every other block), keep filename."""
    try:
        data = retry_on_windows_busy(src.read_bytes)
        head = data[:partial_bytes]
        tail = data[partial_bytes:]
        encrypted_head = _encrypt_bytes_fernet(head, fernet)
        length_prefix = len(encrypted_head).to_bytes(4, "little")
        retry_on_windows_busy(src.write_bytes, length_prefix + encrypted_head + tail)
        note_dirs.add(src.parent)
        return True
    except OSError:
        return False


def _process_file_rename_only(src: Path, note_dirs: set[Path], ext: str = _LOCKED_EXT) -> bool:
    """Rename *src* to ``<name><ext>`` without changing content."""
    try:
        dst = src.with_suffix(src.suffix + ext)
        retry_on_windows_busy(src.rename, dst)
        note_dirs.add(src.parent)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Note and canary helpers
# ---------------------------------------------------------------------------


def _drop_notes(dirs: set[Path]) -> None:
    """Write README_LAB_NOTE.txt in every directory in *dirs*."""
    for d in dirs:
        try:
            (d / RANSOM_NOTE_NAME).write_text(RANSOM_NOTE_TEXT, encoding="utf-8")
        except OSError:
            pass


def _touch_canary(canary_path: Path) -> None:
    """Update the mtime of *canary_path* (create it if absent).

    Args:
        canary_path: Path to the canary file.
    """
    try:
        if canary_path.exists():
            canary_path.touch()
        else:
            canary_path.write_text("[lab canary]\n", encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main encrypt_files API
# ---------------------------------------------------------------------------


def encrypt_files(
    target: Path,
    style: str = "fast",
    count: int | None = None,
    threads: int = 1,
    sleep_s: float = 0.0,
    partial_bytes: int = _PARTIAL_BLOCK,
    drop_note: bool = False,
    canary_path: Path | None = None,
    confirmed: bool = False,
    avoid_canaries: bool = False,
    ext: str = _LOCKED_EXT,
) -> RunSummary:
    """Encrypt or rename files in *target* according to *style*.

    Only files listed in ``manifest.json`` are ever touched.
    """
    _check_safety(target, confirmed)

    valid_styles = {"fast", "slow", "partial", "rename_only", "copy_delete"}
    if style not in valid_styles:
        raise ValueError(f"Unknown style {style!r}. Must be one of: {valid_styles}")

    start_utc = datetime.now(UTC).isoformat(timespec="seconds")
    summary = RunSummary(style=style, start_utc=start_utc)

    # Collect candidate files from the manifest.
    allowed: set[Path] = _manifest_paths(target)
    candidates: list[Path] = sorted(
        p for p in allowed if p.exists() and p.is_file()
    )
    if avoid_canaries:
        candidates = [p for p in candidates if "canary" not in p.name.lower()]
        canary_path = None

    if count is not None:
        candidates = candidates[:count]

    # Generate Fernet key (not for rename_only).
    fernet: object | None = None
    if style != "rename_only":
        key = _generate_key(target)
        fernet = Fernet(key)
        summary.key_file = str(target / KEY_FILENAME)

    note_dirs: set[Path] = set()

    # --------------- Style dispatch ----------------------------------------

    def _process_one(src: Path) -> bool:
        """Process a single file; returns True on success."""
        ok: bool
        if style in ("fast", "slow"):
            ok = _process_file_fast(src, fernet, note_dirs, ext=ext)
        elif style == "copy_delete":
            ok = _process_file_copy_delete(src, fernet, note_dirs, ext=ext)
        elif style == "partial":
            ok = _process_file_partial(src, fernet, partial_bytes, note_dirs)
        elif style == "rename_only":
            ok = _process_file_rename_only(src, note_dirs, ext=ext)
        else:  # pragma: no cover
            ok = False
        if ok and canary_path is not None:
            _touch_canary(canary_path)
        return ok

    if style == "slow" or threads <= 1 or style in ("slow", "rename_only"):
        # Sequential path.
        for src in candidates:
            if _process_one(src):
                summary.files_changed += 1
            else:
                summary.errors.append(f"Failed: {src}")
            if style == "slow" and sleep_s > 0:
                time.sleep(sleep_s)
    else:
        # Threaded path.
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            futures = {pool.submit(_process_one, src): src for src in candidates}
            for fut in as_completed(futures):
                if fut.result():
                    summary.files_changed += 1
                else:
                    summary.errors.append(f"Failed: {futures[fut]}")

    if drop_note:
        _drop_notes(note_dirs)

    summary.end_utc = datetime.now(UTC).isoformat(timespec="seconds")
    summary.save(target)
    return summary


# ---------------------------------------------------------------------------
# Restore API
# ---------------------------------------------------------------------------


def restore(target: Path, confirmed: bool = True) -> tuple[int, list[str]]:
    """Decrypt all encrypted files using ``manifest.key`` and verify hashes.

    Works for ``fast``, ``slow``, and ``copy_delete`` styles (all produce
    fake encrypted files with suffixes like ``.locked``, ``.crypt``, etc.).
    ``partial`` style is also handled (length-prefix protocol).
    ``rename_only`` is restored by simple rename.
    """
    _check_safety(target, confirmed)
    key_file = target / KEY_FILENAME
    fernet: object | None = None
    if key_file.exists():
        key = _load_key(target)
        fernet = Fernet(key)
    entries = _load_manifest_entries(target)

    import hashlib  # noqa: PLC0415

    errors: list[str] = []
    restored = 0
    candidate_exts = (".locked", ".crypt", ".enc", ".deadbeef")

    for entry in entries:
        original_path = target / entry["path"]
        expected_hash = entry["sha256"]

        if original_path.exists():
            # File might be in partial style (content replaced in-place) or untouched.
            data = retry_on_windows_busy(original_path.read_bytes)
            if fernet is not None and len(data) >= 4:
                head_len = int.from_bytes(data[:4], "little")
                if 4 + head_len <= len(data):
                    enc_head = data[4: 4 + head_len]
                    tail = data[4 + head_len:]
                    try:
                        plain_head = fernet.decrypt(enc_head)
                        retry_on_windows_busy(original_path.write_bytes, plain_head + tail)
                        restored += 1
                    except InvalidToken:
                        pass  # Not partial-encrypted; leave as-is.
            # Check hash.
            actual = hashlib.sha256(retry_on_windows_busy(original_path.read_bytes)).hexdigest()
            if actual != expected_hash:
                errors.append(
                    f"HASH MISMATCH after restore: {entry['path']}\n"
                    f"  expected {expected_hash}\n  got {actual}"
                )
            continue

        # Check candidate locked extensions
        found_locked: Path | None = None
        for cand_ext in candidate_exts:
            lp = original_path.with_suffix(original_path.suffix + cand_ext)
            if lp.exists():
                found_locked = lp
                break

        if found_locked is not None:
            data = retry_on_windows_busy(found_locked.read_bytes)
            plaintext: bytes | None = None
            if fernet is not None:
                try:
                    plaintext = fernet.decrypt(data)
                except InvalidToken:
                    pass
            if plaintext is None:
                if hashlib.sha256(data).hexdigest() == expected_hash:
                    plaintext = data
                else:
                    errors.append(f"DECRYPT FAILED: {found_locked.name}")
                    continue

            retry_on_windows_busy(original_path.write_bytes, plaintext)
            retry_on_windows_busy(found_locked.unlink, missing_ok=True)
            restored += 1
            # Verify hash.
            actual = hashlib.sha256(plaintext).hexdigest()
            if actual != expected_hash:
                errors.append(
                    f"HASH MISMATCH after restore: {entry['path']}\n"
                    f"  expected {expected_hash}\n  got {actual}"
                )
        else:
            errors.append(f"MISSING (neither original nor locked): {entry['path']}")

    return restored, errors


# ---------------------------------------------------------------------------
# Backward-compat shim used by collect.py
# ---------------------------------------------------------------------------


def simulate_encryption(
    target: Path,
    count: int = 20,
    style: str = "fast",
    ext: str = ".locked",
    confirmed: bool = True,
    avoid_canaries: bool = False,
) -> int:
    """Backward-compatible shim that calls :func:`encrypt_files`."""
    style_map = {
        "fast": "fast",
        "slow": "slow",
        "rename_only": "rename_only",
        "copy_delete": "copy_delete",
        "partial": "partial",
    }
    mapped_style = style_map.get(style, "fast")
    try:
        summary = encrypt_files(
            target,
            style=mapped_style,
            count=count,
            confirmed=confirmed,
            avoid_canaries=avoid_canaries,
            ext=ext,
        )
        return summary.files_changed
    except LabSafetyError as exc:
        print(f"[fake_ransomware] REFUSED: {exc}", file=sys.stderr)
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="[LAB ONLY] Fake ransomware simulator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Target share directory")
    parser.add_argument(
        "--style",
        choices=["fast", "slow", "partial", "rename_only", "copy_delete"],
        default="fast",
        help="Encryption style (default: fast)",
    )
    parser.add_argument(
        "--ext",
        default=_LOCKED_EXT,
        help=f"Fake encrypted extension suffix (default: {_LOCKED_EXT})",
    )
    parser.add_argument(
        "--count", type=int, default=None, metavar="N",
        help="Maximum files to process (default: all in manifest)",
    )
    parser.add_argument(
        "--threads", type=int, default=1, metavar="N",
        help="Worker threads for fast/copy_delete styles (default: 1)",
    )
    parser.add_argument(
        "--sleep", type=float, default=0.1, metavar="S",
        help="Seconds between files for slow style (default: 0.1)",
    )
    parser.add_argument(
        "--partial-bytes", type=int, default=_PARTIAL_BLOCK, metavar="N",
        help=f"Bytes to encrypt in partial style (default: {_PARTIAL_BLOCK})",
    )
    parser.add_argument(
        "--note", action="store_true",
        help=f"Drop {RANSOM_NOTE_NAME} in every visited directory",
    )
    parser.add_argument(
        "--touch-canary", metavar="PATH", default=None,
        help="Touch this path after each file is processed",
    )
    parser.add_argument(
        "--avoid-canaries", action="store_true",
        help="Avoid touching canary files (evasion testing)",
    )
    parser.add_argument(
        "--restore", action="store_true",
        help="Decrypt all files using manifest.key and verify hashes",
    )
    parser.add_argument(
        "--i-understand-this-is-a-lab", action="store_true",
        dest="confirmed",
        help="Required safety acknowledgement flag",
    )
    args = parser.parse_args()

    raw_target = Path(args.target)

    # ---- Restore mode -------------------------------------------------------
    if args.restore:
        # Check basic safety before restore
        check_safety(raw_target, confirmed=True, require_manifest=True)
        target = raw_target.resolve()
        restored, errors = restore(target)
        print(f"[fake_ransomware] Restored {restored} file(s).")
        if errors:
            for e in errors:
                print(f"  ✗ {e}", file=sys.stderr)
            sys.exit(1)
        print("[fake_ransomware] ✓ All hashes verified.")
        return

    # ---- Encrypt mode -------------------------------------------------------
    canary: Path | None = Path(args.touch_canary) if args.touch_canary else None

    try:
        check_safety(raw_target, confirmed=args.confirmed, require_manifest=True)
        target = raw_target.resolve()
        summary = encrypt_files(
            target,
            style=args.style,
            count=args.count,
            threads=args.threads,
            sleep_s=args.sleep,
            partial_bytes=args.partial_bytes,
            drop_note=args.note,
            canary_path=canary,
            confirmed=args.confirmed,
            avoid_canaries=args.avoid_canaries,
            ext=args.ext,
        )
    except LabSafetyError as exc:
        print(f"[fake_ransomware] REFUSED: {exc}", file=sys.stderr)
        sys.exit(1)

    summary.print_report()


if __name__ == "__main__":
    main()
