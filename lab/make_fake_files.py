"""
lab/make_fake_files.py – Create a realistic fake office-share tree for lab use.

⚠️  LAB ONLY – never import from production code.

Creates a directory tree that looks like a real SMB share (docx, xlsx, pdf,
jpg, png, txt, csv) with per-format realistic headers/structure, a hidden
marker file, and a SHA-256 manifest so ``fake_ransomware.py`` can verify
every file before and after encryption.

Usage::

    python lab/make_fake_files.py --target /mnt/share --count 200
    python lab/make_fake_files.py --target /mnt/share --verify

The target directory is created if it does not exist.  The marker and manifest
are always written (or refreshed) on every run.

Public API
----------
- :func:`create_fake_files` – seed the tree, write marker + manifest.
- :func:`verify_manifest`   – check SHA-256 of every listed file.
- :func:`restore_files`     – strip fake extensions + re-seed missing files.

Marker files written
--------------------
- ``.shareguard_lab_marker`` – canonical hidden name (Part A).
- ``SHAREGUARD_LAB_MARKER``  – legacy name (accepted by Part B scripts).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import struct
import sys
import zipfile
from pathlib import Path
from typing import TypedDict

from lab.safety import (
    KEY_FILENAME,
    MANIFEST_FILENAME,
    MARKER_FILENAME,
    MARKER_LEGACY,
    LabSafetyError,
    check_safety,
    load_lab_config,
    retry_on_windows_busy,
)

__all__: list[str] = ["create_fake_files", "verify_manifest", "restore_files", "LabSafetyError"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MARKER_FILENAME = ".shareguard_lab_marker"
MARKER_LEGACY = "SHAREGUARD_LAB_MARKER"
MANIFEST_FILENAME = "manifest.json"
MANIFEST_VERSION = 1

_SUBDIRS: list[str] = [
    "documents/reports",
    "documents/contracts",
    "documents/templates",
    "spreadsheets/finance",
    "spreadsheets/hr",
    "images/photos",
    "images/logos",
    "backups",
    "projects/alpha",
    "projects/beta",
]

# (extension, weight, min_bytes, max_bytes)
_EXT_CONFIG: list[tuple[str, int, int, int]] = [
    (".docx",  8, 8_000,   80_000),
    (".xlsx",  6, 4_000,   40_000),
    (".pdf",   8, 20_000, 200_000),
    (".txt",   6,    512,  16_000),
    (".csv",   4,  2_000,  20_000),
    (".pptx",  4, 16_000, 120_000),
    (".odt",   3,  8_000,  60_000),
    (".jpg",  10, 50_000, 800_000),
    (".png",   6, 20_000, 200_000),
]

# ---------------------------------------------------------------------------
# Per-extension realistic content generators
# ---------------------------------------------------------------------------


def _rand_text(rng: random.Random, lines: int = 20) -> str:
    """Generate a block of random-looking office prose."""
    words = [
        "report", "summary", "update", "review", "draft", "final", "budget",
        "plan", "schedule", "meeting", "project", "analysis", "output",
        "result", "notes", "action", "item", "data", "client", "quarter",
        "revenue", "forecast", "target", "deliverable", "milestone", "risk",
    ]
    out: list[str] = []
    for _ in range(lines):
        out.append(" ".join(rng.choices(words, k=rng.randint(6, 14))))
    return "\n".join(out) + "\n"


def _rand_csv(rng: random.Random, rows: int = 50) -> str:
    """Generate realistic-looking CSV data."""
    headers = ["id", "name", "department", "amount", "date", "status"]
    depts = ["Engineering", "Finance", "HR", "Marketing", "Sales", "Legal"]
    statuses = ["open", "closed", "pending", "approved", "rejected"]
    lines = [",".join(headers)]
    for i in range(1, rows + 1):
        lines.append(
            f"{i},User_{rng.randint(1000, 9999)},"
            f"{rng.choice(depts)},"
            f"{rng.uniform(100, 50000):.2f},"
            f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d},"
            f"{rng.choice(statuses)}"
        )
    return "\n".join(lines) + "\n"


def _make_ooxml_stub(rng: random.Random, size: int) -> bytes:
    """Minimal Office Open XML ZIP stub (docx/xlsx/pptx/odt look-alikes)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            "</Types>",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            "</Relationships>",
        )
        # Pad with random XML content to reach approximately *size* bytes.
        padding_size = max(0, size - buf.tell() - 256)
        zf.writestr(
            "word/document.xml",
            "<?xml version='1.0'?><body><p>"
            + _rand_text(rng, lines=max(1, padding_size // 80))
            + "</p></body>",
        )
    return buf.getvalue()


def _make_pdf(rng: random.Random, size: int) -> bytes:
    """Minimal PDF with %PDF-1.4 header and random body."""
    body = _rand_text(rng, lines=max(1, size // 80))
    header = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    stream = body.encode("latin-1", errors="replace")
    # Pad to approximate size.
    pad = max(0, size - len(header) - len(stream) - 20)
    trailer = b"\n%%EOF\n"
    return header + stream + bytes(rng.getrandbits(8) for _ in range(pad)) + trailer


def _make_jpg(rng: random.Random, size: int) -> bytes:
    """JFIF JPEG stub: SOI + APP0 marker + random body + EOI."""
    # SOI
    header = bytes([0xFF, 0xD8])
    # APP0 (JFIF)
    header += bytes([0xFF, 0xE0, 0x00, 0x10]) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    body_size = max(0, size - len(header) - 2)
    body = bytes(rng.getrandbits(8) for _ in range(body_size))
    eoi = bytes([0xFF, 0xD9])
    return header + body + eoi


def _make_png(rng: random.Random, size: int) -> bytes:
    """PNG stub: signature + IHDR chunk + IDAT with random data + IEND."""
    sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk
    w, h = 640, 480
    ihdr_data = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    ihdr_crc = _crc32(b"IHDR" + ihdr_data)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    # IDAT with random data
    idat_size = max(0, size - len(sig) - len(ihdr) - 24)
    idat_data = bytes(rng.getrandbits(8) for _ in range(idat_size))
    idat_crc = _crc32(b"IDAT" + idat_data)
    idat = struct.pack(">I", idat_size) + b"IDAT" + idat_data + struct.pack(">I", idat_crc)
    # IEND
    iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    return sig + ihdr + idat + iend


def _crc32(data: bytes) -> int:
    """Compute CRC-32 checksum for PNG chunks."""
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def _make_content(ext: str, size: int, rng: random.Random) -> bytes:
    """Dispatch to the right content generator for *ext*."""
    if ext in (".docx", ".xlsx", ".pptx", ".odt"):
        return _make_ooxml_stub(rng, size)
    if ext == ".pdf":
        return _make_pdf(rng, size)
    if ext == ".txt":
        return _rand_text(rng, lines=max(1, size // 60)).encode("utf-8")
    if ext == ".csv":
        return _rand_csv(rng, rows=max(1, size // 60)).encode("utf-8")
    if ext == ".jpg":
        return _make_jpg(rng, size)
    if ext == ".png":
        return _make_png(rng, size)
    # Fallback: random bytes (for any extension not listed above).
    return bytes(rng.getrandbits(8) for _ in range(size))


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of *path*'s contents.

    Args:
        path: Path to read.

    Returns:
        64-character lowercase hex string.
    """
    def _read_hash() -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    return retry_on_windows_busy(_read_hash)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class ManifestEntry(TypedDict):
    """One entry in the manifest JSON."""

    path: str    # relative to target root, forward-slash separated
    sha256: str  # hex digest


def _write_manifest(target: Path, entries: list[ManifestEntry]) -> Path:
    """Write (or overwrite) ``manifest.json`` in *target*.

    Args:
        target: Root directory.
        entries: List of :class:`ManifestEntry` dicts.

    Returns:
        Path to the written manifest file.
    """
    manifest_path = target / MANIFEST_FILENAME
    payload = {"version": MANIFEST_VERSION, "files": entries}
    retry_on_windows_busy(lambda: manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8"))
    return manifest_path


def load_manifest(target: Path) -> list[ManifestEntry]:
    """Load and return entries from ``manifest.json`` in *target*.

    Args:
        target: Root directory.

    Returns:
        List of :class:`ManifestEntry` dicts.

    Raises:
        FileNotFoundError: If ``manifest.json`` does not exist.
        ValueError: If the manifest format is unrecognised.
    """
    manifest_path = target / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found in '{target}'")
    content = retry_on_windows_busy(lambda: manifest_path.read_text(encoding="utf-8"))
    data = json.loads(content)
    if data.get("version") != MANIFEST_VERSION:
        raise ValueError(f"Unknown manifest version: {data.get('version')}")
    return data["files"]  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Marker helper
# ---------------------------------------------------------------------------


def _write_markers(target: Path) -> None:
    """Write both the canonical and legacy marker files in *target*."""
    retry_on_windows_busy(lambda: (target / MARKER_FILENAME).write_text("shareguard-lab\n", encoding="utf-8"))
    retry_on_windows_busy(lambda: (target / MARKER_LEGACY).write_text("shareguard-lab\n", encoding="utf-8"))


def _check_marker(target: Path) -> None:
    """Refuse to run unless at least one marker file exists in *target*."""
    if not (target / MARKER_FILENAME).exists() and not (target / MARKER_LEGACY).exists():
        print(
            f"[make_fake_files] REFUSED: neither '{MARKER_FILENAME}' nor "
            f"'{MARKER_LEGACY}' found in '{target}'.",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_fake_files(
    target: Path,
    count: int = 200,
    seed: int = 42,
    confirmed: bool = True,
    config_path: Path | None = None,
) -> list[Path]:
    """Create *count* fake files, write markers, and write ``manifest.json``.

    Existing files are not overwritten (their hashes are re-used in the
    manifest).  The manifest always reflects the *current* on-disk state.

    Args:
        target: Root directory of the lab share (created if absent).
        count: Number of fake files to create.
        seed: Random seed for reproducibility.
        confirmed: Confirmation flag.
        config_path: Optional path to custom lab configuration.

    Returns:
        List of :class:`pathlib.Path` objects for every file listed in the
        manifest (created or pre-existing).
    """
    check_safety(target, confirmed=confirmed, require_marker=False, require_manifest=False, config_path=config_path)
    target.mkdir(parents=True, exist_ok=True)
    _write_markers(target)

    rng = random.Random(seed)
    exts = [ext for ext, _, _, _ in _EXT_CONFIG]
    weights = [w for _, w, _, _ in _EXT_CONFIG]
    size_map = {ext: (mn, mx) for ext, _, mn, mx in _EXT_CONFIG}

    # Ensure subdirectory tree exists.
    for sub in _SUBDIRS:
        (target / sub).mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    for i in range(count):
        sub = rng.choice(_SUBDIRS)
        (ext,) = rng.choices(exts, weights=weights, k=1)
        name = f"file_{i:04d}{ext}"
        path = target / sub / name
        if not path.exists():
            mn, mx = size_map[ext]
            size = rng.randint(mn, mx)
            content = _make_content(ext, size, rng)
            retry_on_windows_busy(lambda p=path, c=content: p.write_bytes(c))
        created.append(path)

    # Build and write manifest.
    entries: list[ManifestEntry] = [
        {"path": p.relative_to(target).as_posix(), "sha256": sha256_file(p)}
        for p in created
    ]
    _write_manifest(target, entries)
    return created


def verify_manifest(
    target: Path,
    confirmed: bool = True,
    config_path: Path | None = None,
) -> tuple[bool, list[str]]:
    """Verify the SHA-256 hash of every file listed in ``manifest.json``.

    Args:
        target: Root directory of the lab share.
        confirmed: Confirmation flag.
        config_path: Optional path to custom lab configuration.

    Returns:
        A ``(ok, errors)`` tuple where *ok* is True when all hashes match and
        *errors* is a list of human-readable mismatch descriptions.
    """
    check_safety(target, confirmed=confirmed, require_marker=True, require_manifest=True, config_path=config_path)
    entries = load_manifest(target)
    errors: list[str] = []
    for entry in entries:
        p = target / entry["path"]
        if not p.exists():
            errors.append(f"MISSING: {entry['path']}")
            continue
        actual = sha256_file(p)
        if actual != entry["sha256"]:
            errors.append(
                f"HASH MISMATCH: {entry['path']}\n"
                f"  expected {entry['sha256']}\n"
                f"  got      {actual}"
            )
    return len(errors) == 0, errors


def restore_files(
    target: Path,
    count: int = 200,
    seed: int = 42,
    fake_extensions: tuple[str, ...] = (".locked", ".crypt", ".enc", ".deadbeef"),
    confirmed: bool = True,
    config_path: Path | None = None,
) -> int:
    """Undo fake-ransomware renames and re-create any missing files.

    For files that were encrypted (content changed), restoration must be done
    via ``fake_ransomware.restore()`` before calling this function.  This
    function only handles the *rename-only* case (strips fake extensions) and
    re-seeds any files that are still absent.

    Args:
        target: Root directory of the lab share.
        count: Passed to :func:`create_fake_files` for re-seeding.
        seed: Passed to :func:`create_fake_files` for re-seeding.
        fake_extensions: Extension suffixes to strip.
        confirmed: Confirmation flag.
        config_path: Optional path to custom lab configuration.

    Returns:
        Number of files renamed back (extension stripped).
    """
    check_safety(target, confirmed=confirmed, require_marker=True, require_manifest=True, config_path=config_path)
    restored = 0
    for p in list(target.rglob("*")):
        if p.is_file() and p.suffix in fake_extensions:
            original = p.with_suffix("")
            if not original.exists():
                retry_on_windows_busy(lambda src=p, dst=original: src.rename(dst))
                restored += 1
            else:
                retry_on_windows_busy(lambda src=p: src.unlink(missing_ok=True))

    # Remove stale ransom notes.
    for note in target.rglob("README_LAB_NOTE.txt"):
        retry_on_windows_busy(lambda n=note: n.unlink(missing_ok=True))

    # Re-create any files that are still missing.
    create_fake_files(target, count=count, seed=seed, confirmed=confirmed, config_path=config_path)
    return restored


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="[LAB ONLY] Create fake share files for ShareGuard collection runs."
    )
    parser.add_argument("--target", required=True, help="Target directory")
    parser.add_argument("--count", type=int, default=200, help="Number of files to create")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--verify", action="store_true", help="Verify manifest hashes and exit"
    )
    parser.add_argument(
        "--i-understand-this-is-a-lab",
        action="store_true",
        help="Confirmation flag (required for all operations)",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    if not args.i_understand_this_is_a_lab:
        print(
            "[make_fake_files] REFUSED: pass --i-understand-this-is-a-lab to confirm this is an isolated lab.",
            file=sys.stderr,
        )
        sys.exit(1)

    raw_target = Path(args.target)

    try:
        if args.verify:
            check_safety(raw_target, confirmed=args.i_understand_this_is_a_lab, require_marker=True, require_manifest=True)
            target = raw_target.resolve()
            ok, errors = verify_manifest(target, confirmed=args.i_understand_this_is_a_lab)
            if ok:
                print("[make_fake_files] ✓ All hashes verified.")
            else:
                for e in errors:
                    print(f"[make_fake_files] ✗ {e}", file=sys.stderr)
                sys.exit(1)
            return

        check_safety(raw_target, confirmed=args.i_understand_this_is_a_lab, require_marker=False, require_manifest=False)
        target = raw_target.resolve()
        paths = create_fake_files(target, count=args.count, seed=args.seed, confirmed=args.i_understand_this_is_a_lab)
        print(
            f"[make_fake_files] ✓ Created/verified {len(paths)} file(s) in '{target}'.\n"
            f"  Marker   : {target / MARKER_FILENAME}\n"
            f"  Manifest : {target / MANIFEST_FILENAME}"
        )
    except LabSafetyError as err:
        print(f"[make_fake_files] REFUSED: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
