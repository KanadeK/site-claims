"""Build a bounded file-claim graph without importing the inspected environment."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import os
import re
import stat
from collections import defaultdict
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PureWindowsPath


class ScanError(Exception):
    """The requested scan could not produce a complete bounded report."""


@dataclass(frozen=True)
class Limits:
    max_distributions: int = 5_000
    max_entries: int = 200_000
    max_root_entries: int = 100_000
    max_record_bytes: int = 16 * 1024 * 1024
    max_metadata_bytes: int = 1024 * 1024
    max_manifest_bytes: int = 64 * 1024 * 1024
    max_hash_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        if any(type(value) is not int or value < 1 for value in vars(self).values()):
            raise ValueError("all limits must be positive integers")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _file_info(root: Path, relative: str) -> os.stat_result:
    """Check every component; never deliberately follow a link inside root."""
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        info = current.lstat()
        if _linked(info):
            raise ScanError("symlink or reparse point is not read")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ScanError("ancestor is not a directory")
    if not stat.S_ISREG(info.st_mode):
        raise ScanError("target is not a regular file")
    return info


def _open_checked(root: Path, relative: str):
    expected = _file_info(root, relative)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(root / relative, flags)
    try:
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode) or not os.path.samestat(expected, actual):
            raise ScanError("file changed while opening")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _read(root: Path, relative: str, limit: int) -> bytes:
    with _open_checked(root, relative) as stream:
        if os.fstat(stream.fileno()).st_size > limit:
            raise ScanError("metadata byte limit exceeded")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ScanError("metadata byte limit exceeded")
    return content


def _record_path(raw: str) -> tuple[str | None, str | None]:
    """Normalize installed RECORD paths; keep outside claims as metadata only."""
    if not raw or len(raw) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return None, "invalid_path"
    if PureWindowsPath(raw).drive or raw.startswith(("/", "\\")):
        return None, "external_path"
    # Backslashes are separators only on Windows according to the installed spec.
    if "\\" in raw:
        if os.name == "nt":
            raw = raw.replace("\\", "/")
        else:
            return None, "unsupported_path"
    parts = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None, "external_path"
            parts.pop()
        else:
            # Prevent Windows device names and alternate data streams from being opened.
            if os.name == "nt" and (
                ":" in part
                or part.endswith((" ", "."))
                or part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                or re.fullmatch(r"(?:COM|LPT)[1-9¹²³](?:\..*)?", part, re.I)
                or any(char in part for char in '<>"|?*')
            ):
                return None, "unsupported_path"
            parts.append(part)
    if not parts or raw.endswith("/"):
        return None, "invalid_path"
    return "/".join(parts), None


def _digest(raw: str) -> tuple[str, bytes] | None:
    if not raw:
        return None
    algorithm, separator, value = raw.partition("=")
    if not separator or algorithm not in {"sha256", "sha384", "sha512"}:
        raise ValueError("unsupported or invalid hash (supported: sha256/384/512)")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("hash must use unpadded URL-safe base64")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid hash encoding") from error
    if len(decoded) != hashlib.new(algorithm).digest_size:
        raise ValueError("invalid hash length")
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("noncanonical hash encoding")
    return algorithm, decoded


def _inspect(root: Path, path: str, claims: list[dict], budget: list[int]) -> dict:
    try:
        with _open_checked(root, path) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > budget[0]:
                return {"state": "hash_limit", "size": before.st_size}
            digests = {
                item["digest"][0]: hashlib.new(item["digest"][0])
                for item in claims
                if item["digest"]
            }
            size = 0
            while True:
                block = stream.read(min(65536, budget[0] + 1))
                if not block:
                    break
                size += len(block)
                budget[0] -= len(block)
                if budget[0] < 0:
                    return {"state": "hash_limit"}
                for digest in digests.values():
                    digest.update(block)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                return {"state": "changed_during_read"}
            for claim in claims:
                digest = claim["digest"]
                claim["matches_disk"] = (
                    None if digest is None else digests[digest[0]].digest() == digest[1]
                )
                claim["size_matches_disk"] = (
                    None if claim["size"] is None else claim["size"] == size
                )
            return {"state": "read", "size": size}
    except FileNotFoundError:
        return {"state": "missing"}
    except (OSError, ScanError, ValueError) as error:
        return {"state": "unreadable", "reason": type(error).__name__}


def _agreement(claims: list[dict]) -> str:
    """Only compare hashes using the same algorithm; never guess across algorithms."""
    groups = defaultdict(set)
    for item in claims:
        if item["digest"]:
            algorithm, digest = item["digest"]
            groups[algorithm].add(digest)
    sizes = {item["size"] for item in claims if item["size"] is not None}
    if any(len(group) > 1 for group in groups.values()) or len(sizes) > 1:
        return "different"
    if all(item["digest"] for item in claims) and len(groups) == 1:
        return "identical"
    return "unknown"


def scan(
    site_packages: str | Path,
    *,
    removing: tuple[str, ...] | list[str] = (),
    verify: bool = False,
    limits: Limits | None = None,
) -> dict:
    """Inspect one explicit library root. Hash shared paths, or all claims with verify.

    Report paths use Windows normcase or exact POSIX spelling. No imports, network access,
    writes, or interpreter startup from the inspected root are performed.
    """
    limits = limits or Limits()
    try:
        root = Path(site_packages).resolve(strict=True)
        if not root.is_dir():
            raise ScanError("site-packages must be a directory")
        entries = []
        with os.scandir(root) as iterator:
            for count, entry in enumerate(iterator, 1):
                if count > limits.max_root_entries:
                    raise ScanError("root entry limit exceeded")
                if entry.name.endswith((".dist-info", ".egg-info")):
                    entries.append(entry.name)
        entries.sort()
    except (OSError, RuntimeError) as error:
        raise ScanError(f"cannot inspect library root ({type(error).__name__})") from error
    if not entries:
        raise ScanError("no .dist-info or .egg-info metadata found in the requested root")
    if len(entries) > limits.max_distributions:
        raise ScanError("distribution limit exceeded")
    owners = []
    files = defaultdict(list)
    issues = []
    excluded = []
    total = 0
    manifest_bytes = 0

    def read_metadata(relative, limit):
        nonlocal manifest_bytes
        data = _read(root, relative, limit)
        manifest_bytes += len(data)
        if manifest_bytes > limits.max_manifest_bytes:
            raise _TotalLimit("total manifest byte limit exceeded")
        return data

    def issue(owner, code, detail, path=None):
        item = {"owner": owner, "code": code, "detail": detail}
        if path is not None:
            item["path"] = path
        issues.append(item)

    for directory in entries:
        if directory.endswith(".egg-info"):
            issue(directory, "legacy_metadata", "legacy .egg-info is not inspected")
            continue
        try:
            metadata = BytesParser().parsebytes(
                read_metadata(f"{directory}/METADATA", limits.max_metadata_bytes),
                headersonly=True,
            )
            names, versions = (
                metadata.get_all("Name", []),
                metadata.get_all("Version", []),
            )
            if len(names) != 1 or len(versions) != 1 or metadata.defects:
                raise ValueError("exactly one Name and Version header required")
            name, version = str(names[0]), str(versions[0])
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
                raise ValueError("invalid distribution name")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,199}", version):
                raise ValueError("invalid or unsupported version label")
        except _TotalLimit:
            raise
        except (OSError, ScanError, ValueError) as error:
            issue(directory, "metadata_unreadable", type(error).__name__)
            continue
        owner = {
            "id": directory,
            "name": name,
            "normalized_name": normalize_name(name),
            "version": version,
        }
        owners.append(owner)
        try:
            content = read_metadata(f"{directory}/RECORD", limits.max_record_bytes).decode("utf-8")
            reader = csv.reader(io.StringIO(content, newline=""), strict=True)
            seen = set()
            for row in reader:
                total += 1
                if total > limits.max_entries:
                    raise _TotalLimit("total RECORD row limit exceeded")
                if len(row) != 3:
                    issue(directory, "invalid_record", "each row must have three fields")
                    continue
                raw, hashed, sized = row
                if len(hashed) > 128 or len(sized) > 20:
                    issue(directory, "invalid_record", "hash or size field too long")
                    hashed, sized = "", ""
                path, problem = _record_path(raw)
                if problem:
                    excluded.append({"owner": directory, "path": raw, "reason": problem})
                    continue
                key = os.path.normcase(path)
                if key in seen:
                    issue(
                        directory,
                        "duplicate_record_path",
                        "path declared more than once",
                        path,
                    )
                    continue
                seen.add(key)
                try:
                    digest = _digest(hashed)
                    if sized and (not re.fullmatch(r"[0-9]{1,20}", sized)):
                        raise ValueError("invalid file size")
                    size = int(sized) if sized else None
                except ValueError as error:
                    issue(directory, "invalid_record", str(error), path)
                    digest, size = None, None
                files[key].append(
                    {
                        "owner": directory,
                        "path": path,
                        "hash": hashed,
                        "size": size,
                        "digest": digest,
                        "matches_disk": None,
                        "size_matches_disk": None,
                    }
                )
            if not seen:
                issue(directory, "empty_record", "no supported file paths declared")
        except _TotalLimit:
            raise
        except ScanError as error:
            issue(directory, "record_unreadable", str(error))
        except (OSError, UnicodeError, csv.Error) as error:
            issue(directory, "record_unreadable", type(error).__name__)

    by_name = defaultdict(list)
    for owner in owners:
        by_name[owner["normalized_name"]].append(owner["id"])
    for name, ids in sorted(by_name.items()):
        if len(ids) > 1:
            issue(name, "duplicate_distribution", ", ".join(ids))
    requested = sorted({normalize_name(name) for name in removing})
    missing = set(requested) - by_name.keys()
    if missing:
        raise ScanError("requested removal names not found: " + ", ".join(sorted(missing)))
    removed_ids = {key for name in requested for key in by_name[name]}
    collisions, checks, risks = [], [], []
    budget = [limits.max_hash_bytes]
    for _key, claims in sorted(files.items()):
        path = claims[0]["path"]
        shared = len(claims) > 1
        disk = (
            _inspect(root, path, claims, budget) if shared or verify else {"state": "not_checked"}
        )
        public = [{k: v for k, v in item.items() if k != "digest"} for item in claims]
        if shared:
            collisions.append(
                {
                    "path": path,
                    "agreement": _agreement(claims),
                    "disk": disk,
                    "claims": public,
                }
            )
            removed = sorted(item["owner"] for item in claims if item["owner"] in removed_ids)
            remaining = sorted(item["owner"] for item in claims if item["owner"] not in removed_ids)
            if removed and remaining:
                risks.append(
                    {
                        "path": path,
                        "removing": removed,
                        "remaining": remaining,
                        "disk_state": disk["state"],
                    }
                )
        if shared or verify:
            bad = disk["state"] != "read" or any(
                item["matches_disk"] is False or item["size_matches_disk"] is False
                for item in claims
            )
            if bad:
                checks.append({"path": path, "disk": disk, "claims": public})
    incomplete = bool(
        issues
        or excluded
        or any(check["disk"]["state"] not in {"read", "missing"} for check in checks)
    )
    return {
        "format_version": 1,
        "scope": "one library root; installed RECORD declarations only",
        "case_policy": "windows-normcase" if os.name == "nt" else "exact",
        "verification": "all" if verify else "shared",
        "distributions": owners,
        "summary": {
            "distributions": len(owners),
            "record_rows": total,
            "claimed_paths": len(files),
            "shared_paths": len(collisions),
            "removal_risks": len(risks),
            "file_findings": len(checks),
            "excluded_claims": len(excluded),
            "metadata_issues": len(issues),
            "unhashed_claims": sum(
                item["digest"] is None for claims in files.values() for item in claims
            ),
            "hash_bytes_read": limits.max_hash_bytes - max(0, budget[0]),
        },
        "coverage_complete": not incomplete,
        "removing": requested,
        "collisions": collisions,
        "removal_risks": risks,
        "file_findings": checks,
        "metadata_issues": issues,
        "excluded_claims": excluded,
        "has_findings": bool(collisions or checks or issues or excluded),
    }


class _TotalLimit(ScanError):
    """Stop before a partial manifest graph is emitted."""
