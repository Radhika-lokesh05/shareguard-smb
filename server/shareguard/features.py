"""
shareguard.features – Per-client behaviour feature aggregation.

Aggregates a sliding window of :class:`~shareguard.parser.AuditEvent` objects
into a :class:`ClientFeatures` dataclass that feeds the rule engine and the
ML model.

Features computed:
- rename_count, delete_count, write_count, read_count
- unique_extensions (post-rename or accessed)
- mean_entropy (of renamed file extensions)
- total_events
- extra metrics:
  - ext_change_count: count of renames changing file extension
  - canary_touch_count: count of canary decoy files accessed
  - ransom_note_count: count of ransom note creations
  - ransom_note_dirs: number of distinct directories with ransom notes
  - files_created_by_client: count of distinct files newly created by client
  - preexisting_files_modified: count of pre-existing files modified
  - preexisting_files_deleted: count of pre-existing files deleted
  - distinct_high_entropy_files: count of distinct files written with high entropy
  - delete_after_copy_count: unlinks of pre-existing files where high-entropy copies were written
  - mean_entropy_written: estimated entropy of written/modified files
  - ops_per_sec: activity rate proxy
  - files_changed: sum of renames, writes, and deletes

All computation is pure and stateless given the event list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from shareguard.canary import is_canary_path
from shareguard.entropy import (
    FileEntropyProvider,
    SimulatedEntropyProvider,
    extension_entropy,
    string_entropy,
)

if TYPE_CHECKING:
    from shareguard.parser import AuditEvent

__all__ = ["ClientFeatures", "compute_features"]

# Common ransom note name patterns (case-insensitive)
_RANSOM_NOTE_RE = re.compile(
    r"(readme.*note.*\.txt|how_to_decrypt.*|decrypt.*\.txt|.*ransom.*\.txt|restore.*files.*\.txt)",
    re.IGNORECASE,
)

# Known ransomware encrypted extensions
_SUSPICIOUS_EXTENSIONS = {
    ".locked",
    ".crypt",
    ".crypto",
    ".enc",
    ".encrypted",
    ".lock",
    ".pay",
    ".crypted",
}

# Standard benign archive/video extensions (commonly single large high-entropy outputs)
_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".iso",
    ".mp4",
    ".mkv",
    ".avi",
}


@dataclass(frozen=True, slots=True)
class ClientFeatures:
    """Aggregated behavioural features for a single client in one window.

    Attributes:
        client_ip: Client IP address.
        username: Samba username.
        window_start: Unix timestamp of the first event in the window.
        window_end: Unix timestamp of the last event in the window.
        rename_count: Number of rename operations.
        delete_count: Number of delete (unlink) operations.
        write_count: Number of write operations.
        read_count: Number of read/open operations.
        unique_extensions: Number of distinct file extensions seen.
        mean_entropy: Mean Shannon entropy of renamed target extensions.
        total_events: Total event count in the window.
        extra: Additional metrics used by specific detection rules.
    """

    client_ip: str
    username: str
    window_start: float
    window_end: float
    rename_count: int = 0
    delete_count: int = 0
    write_count: int = 0
    read_count: int = 0
    unique_extensions: int = 0
    mean_entropy: float = 0.0
    total_events: int = 0
    extra: dict[str, float] = field(default_factory=dict)


def compute_features(
    events: list[AuditEvent],
    client_ip: str,
    username: str,
    entropy_provider: Any = None,
) -> ClientFeatures:
    """Aggregate *events* for a single client into :class:`ClientFeatures`.

    Tracks file lifecycle per client to differentiate between:
    - Creating and deleting self-created temporary files (benign dev).
    - Writing a single archive output (benign zip).
    - Overwriting many distinct pre-existing files with high entropy (ransomware).
    - Writing encrypted copies and deleting pre-existing originals (ransomware).

    Args:
        events: All events in the current window for this client.
        client_ip: Client IP address.
        username: Samba username.

    Returns:
        A :class:`ClientFeatures` instance (all zeros if *events* is empty).
    """
    if not events:
        return ClientFeatures(
            client_ip=client_ip,
            username=username,
            window_start=0.0,
            window_end=0.0,
        )

    sorted_events = sorted(events, key=lambda e: e.ts)
    window_start = sorted_events[0].ts.timestamp()
    window_end = sorted_events[-1].ts.timestamp()
    window_duration = max(1.0, window_end - window_start)

    provider = entropy_provider if entropy_provider is not None else FileEntropyProvider()

    # Pre-pass: Discover known directories in this window to handle folder noise
    known_dirs: set[str] = set()
    from shareguard.parser import get_share_roots

    configured_roots = {r.rstrip("/") for r in get_share_roots().values() if r}

    for evt in sorted_events:
        p = evt.rel_path if evt.rel_path else evt.path
        clean_p = p.replace("\\", "/").rstrip("/")
        norm_raw = evt.path.replace("\\", "/").rstrip("/")

        is_share_root = (
            evt.rel_path == ""
            and (norm_raw in {"", "."} or norm_raw.endswith("/") or norm_raw in configured_roots)
        )
        if is_share_root:
            known_dirs.add("")
            known_dirs.add(clean_p)
            known_dirs.add(norm_raw)

        if evt.path.endswith("/") or (evt.rel_path and evt.rel_path.endswith("/")):
            known_dirs.add(clean_p)
            known_dirs.add(norm_raw)

        if evt.op.lower() in {"mkdirat", "mkdir"}:
            known_dirs.add(clean_p)
            known_dirs.add(norm_raw)

        for target in (evt.rel_path, evt.new_rel_path, evt.path, evt.new_path):
            if target:
                norm_t = target.replace("\\", "/").strip("/")
                parts = norm_t.split("/")
                if len(parts) > 1:
                    for i in range(1, len(parts)):
                        known_dirs.add("/".join(parts[:i]))

    rename_count = 0
    delete_count = 0
    write_count = 0
    read_count = 0
    ext_change_count = 0
    canary_touch_count = 0
    ransom_note_count = 0

    renamed_dst_extensions: list[str] = []
    all_extensions: set[str] = set()
    ransom_dirs: set[str] = set()

    # Track file lifecycle per client in this window
    first_op_per_file: dict[str, str] = {}
    files_created_by_client: set[str] = set()
    preexisting_files: set[str] = set()
    preexisting_files_modified: set[str] = set()
    preexisting_files_deleted: set[str] = set()

    # High-entropy writes tracking (sampled at 'close')
    pending_write_samples: dict[str, tuple[str, str, str, str]] = {}
    distinct_high_entropy_files: set[str] = set()
    high_entropy_written_scores: list[float] = []

    # Directories with suspicious or high-entropy writes
    dir_encrypted_writes: dict[str, set[str]] = {}

    for evt in sorted_events:
        op = evt.op.lower()
        # Prefer relative path for extensions, folder tracking, and canary detection
        path_str = evt.rel_path if evt.rel_path else evt.path
        new_path_str = evt.new_rel_path or evt.new_path

        norm_path = path_str.replace("\\", "/") if path_str else ""
        clean_norm = norm_path.rstrip("/")

        # Check if path is a directory (folder noise from Windows Explorer)
        is_dir = bool(
            path_str == ""
            or evt.path.endswith("/")
            or norm_path.endswith("/")
            or clean_norm in known_dirs
            or evt.path.rstrip("/") in known_dirs
        )

        dirname = "."
        filename = ""
        ext = ""
        if not is_dir:
            idx = norm_path.rfind("/")
            if idx != -1:
                dirname = norm_path[:idx]
                filename = norm_path[idx + 1 :]
            else:
                dirname = "."
                filename = norm_path

            dot_idx = filename.rfind(".")
            ext = filename[dot_idx:].lower() if (dot_idx != -1 and dot_idx != 0) else ""
            if ext:
                all_extensions.add(ext)

        # 1. Canary detection (use relative path where possible)
        p_for_canary = evt.rel_path if evt.rel_path else evt.path
        new_p_canary = evt.new_rel_path if evt.new_rel_path else evt.new_path
        if (p_for_canary and is_canary_path(p_for_canary)) or (new_p_canary and is_canary_path(new_p_canary)):
            canary_touch_count += 1

        # 2. Ransom note detection
        if not is_dir:
            new_fn = new_path_str.replace("\\", "/").rsplit("/", 1)[-1] if new_path_str else ""
            if _RANSOM_NOTE_RE.match(filename) or (new_fn and _RANSOM_NOTE_RE.match(new_fn)):
                ransom_note_count += 1
                ransom_dirs.add(dirname)

        # Check flags for write / create
        args_lower = evt.args.lower()
        args_tokens = set(re.split(r"[\s,|]+", args_lower))
        is_create_op = "0x42" in args_tokens or "creat" in args_lower or "0x40" in args_tokens
        is_write_flag = bool(
            {"0x42", "0x2", "0x02", "0x1", "0x01", "write", "creat", "w"} & args_tokens
            or "write" in args_lower
            or "creat" in args_lower
            or args_lower == "w"
        )

        if not is_dir and path_str not in first_op_per_file:
            first_op_per_file[path_str] = op
            if is_create_op and ext in _ARCHIVE_EXTENSIONS:
                files_created_by_client.add(path_str)
            elif op in {"read"} or (op in {"openat", "open"} and not is_create_op and not is_write_flag):
                preexisting_files.add(path_str)
            else:
                preexisting_files.add(path_str)

        # 4. Operation handling
        if op in {"renameat", "rename"}:
            rename_count += 1
            if new_path_str:
                norm_new = new_path_str.replace("\\", "/")
                new_idx = norm_new.rfind("/")
                new_parent = norm_new[:new_idx] if new_idx != -1 else "."
                new_fn = norm_new[new_idx + 1 :] if new_idx != -1 else norm_new
                new_dot = new_fn.rfind(".")
                new_ext = new_fn[new_dot:].lower() if (new_dot != -1 and new_dot != 0) else ""

                if new_ext:
                    renamed_dst_extensions.append(new_ext)
                    all_extensions.add(new_ext)
                if ext != new_ext or new_ext in _SUSPICIOUS_EXTENSIONS:
                    ext_change_count += 1
                first_op_per_file[new_path_str] = "rename_dest"
                if new_ext in _SUSPICIOUS_EXTENSIONS:
                    dir_encrypted_writes.setdefault(new_parent, set()).add(new_path_str)

        elif op in {"unlinkat", "unlink"}:
            if not is_dir:
                delete_count += 1
                if path_str not in files_created_by_client:
                    preexisting_files_deleted.add(path_str)

        elif op in {"write"} or (op in {"openat", "open"} and is_write_flag):
            if not is_dir:
                write_count += 1
                if path_str in preexisting_files:
                    preexisting_files_modified.add(path_str)
                # Stage for entropy sampling at 'close' event
                pending_write_samples[path_str] = (evt.path, evt.args, ext, dirname)

        elif op in {"close"}:
            # Sample entropy once at close event if file was written
            if not is_dir and path_str in pending_write_samples:
                abs_p, flags, file_ext, file_dir = pending_write_samples.pop(path_str)
                is_suspicious_ext = file_ext in _SUSPICIOUS_EXTENSIONS
                entropy_score = provider.get_entropy(abs_p, flags=flags)
                high_entropy_written_scores.append(entropy_score)
                if entropy_score >= 7.0:
                    distinct_high_entropy_files.add(path_str)
                    if is_suspicious_ext:
                        dir_encrypted_writes.setdefault(file_dir, set()).add(path_str)

        elif op in {"read"} or (op in {"openat", "open"} and not is_write_flag and not is_create_op):
            if not is_dir:
                read_count += 1
        elif op in {"mkdirat"}:
            pass

    # Sample any writes that remained unclosed at end of window
    for remaining_path, (abs_p, flags, file_ext, file_dir) in pending_write_samples.items():
        is_suspicious_ext = file_ext in _SUSPICIOUS_EXTENSIONS
        entropy_score = provider.get_entropy(abs_p, flags=flags)
        high_entropy_written_scores.append(entropy_score)
        if entropy_score >= 7.0:
            distinct_high_entropy_files.add(remaining_path)
            if is_suspicious_ext:
                dir_encrypted_writes.setdefault(file_dir, set()).add(remaining_path)

    # Extension entropy calculation
    if renamed_dst_extensions:
        dist_entropy = extension_entropy(renamed_dst_extensions)
        avg_str_entropy = sum(string_entropy(e.lstrip(".")) for e in renamed_dst_extensions) / len(
            renamed_dst_extensions
        )
        mean_entropy = max(dist_entropy, avg_str_entropy * 2.0)
    else:
        mean_entropy = 0.0

    mean_entropy_written = (
        sum(high_entropy_written_scores) / len(high_entropy_written_scores)
        if high_entropy_written_scores
        else 0.0
    )

    # Delete-after-copy pattern:
    # Pre-existing file deleted in a directory where a suspicious/encrypted write occurred
    delete_after_copy_count = 0
    for deleted_path in preexisting_files_deleted:
        norm_del = deleted_path.replace("\\", "/")
        idx = norm_del.rfind("/")
        del_dir = norm_del[:idx] if idx != -1 else "."
        del_fn = norm_del[idx + 1 :] if idx != -1 else norm_del
        dot_idx = del_fn.rfind(".")
        del_stem = del_fn[:dot_idx] if dot_idx != -1 else del_fn

        # Check if an encrypted sibling exists in the same directory or matching stem
        if del_dir in dir_encrypted_writes:
            encrypted_siblings = dir_encrypted_writes[del_dir]
            for enc in encrypted_siblings:
                enc_norm = enc.replace("\\", "/")
                enc_fn = enc_norm.rsplit("/", 1)[-1]
                enc_dot = enc_fn.rfind(".")
                enc_stem = enc_fn[:enc_dot] if enc_dot != -1 else enc_fn
                enc_ext = enc_fn[enc_dot:].lower() if enc_dot != -1 else ""
                if enc_stem == del_stem or enc_ext in _SUSPICIOUS_EXTENSIONS:
                    delete_after_copy_count += 1
                    break

    total_events = len(sorted_events)
    ops_per_sec = total_events / window_duration
    files_changed = rename_count + write_count + delete_count

    extra: dict[str, float] = {
        "ext_change_count": float(ext_change_count),
        "canary_touch_count": float(canary_touch_count),
        "ransom_note_count": float(ransom_note_count),
        "ransom_note_dirs": float(len(ransom_dirs)),
        "files_created_by_client": float(len(files_created_by_client)),
        "preexisting_files_modified": float(len(preexisting_files_modified)),
        "preexisting_files_deleted": float(len(preexisting_files_deleted)),
        "distinct_high_entropy_files": float(len(distinct_high_entropy_files)),
        "delete_after_copy_count": float(delete_after_copy_count),
        "mean_entropy_written": float(mean_entropy_written),
        "ops_per_sec": float(ops_per_sec),
        "files_changed": float(files_changed),
    }

    return ClientFeatures(
        client_ip=client_ip,
        username=username,
        window_start=window_start,
        window_end=window_end,
        rename_count=rename_count,
        delete_count=delete_count,
        write_count=write_count,
        read_count=read_count,
        unique_extensions=len(all_extensions),
        mean_entropy=round(mean_entropy, 3),
        total_events=total_events,
        extra=extra,
    )
