"""CLI: inspect an explicit directory without starting its Python interpreter."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import Limits, ScanError, scan


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _quote(value) -> str:
    return json.dumps(value, ensure_ascii=True)


def _text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"Distributions: {summary['distributions']}; claimed paths: {summary['claimed_paths']}; "
        f"shared paths: {summary['shared_paths']}; removal risks: {summary['removal_risks']}",
        f"Coverage: {'complete within declared scope' if report['coverage_complete'] else 'INCOMPLETE'}; "
        f"hashing: {report['verification']}; unhashed claims: {summary['unhashed_claims']}",
    ]
    for collision in report["collisions"]:
        owners = [item["owner"] for item in collision["claims"]]
        matches = [item["owner"] for item in collision["claims"] if item["matches_disk"] is True]
        lines.append(
            f"SHARED {_quote(collision['path'])}: expected={collision['agreement']}; "
            f"disk={collision['disk']['state']}; owners={_quote(owners)}; matches={_quote(matches)}"
        )
    for risk in report["removal_risks"]:
        lines.append(
            f"REMOVAL-RISK {_quote(risk['path'])}: removing={_quote(risk['removing'])}; "
            f"remaining={_quote(risk['remaining'])}"
        )
    for item in report["file_findings"]:
        lines.append(
            f"FILE {_quote(item['path'])}: disk={item['disk']['state']}; check JSON for claimant details"
        )
    for item in report["metadata_issues"]:
        lines.append(f"METADATA {_quote(item)}")
    for item in report["excluded_claims"]:
        lines.append(f"EXCLUDED {_quote(item)}")
    lines.append("Read-only RECORD evidence. Shared bytes can still be removed by an uninstaller.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Explain installed Python file ownership and hypothetical uninstall risks. Read-only."
    )
    parser.add_argument("--version", action="version", version=f"site-claims {__version__}")
    parser.add_argument(
        "site_packages", help="one explicit site-packages directory (not a venv root)"
    )
    parser.add_argument(
        "--removing",
        action="append",
        default=[],
        metavar="DISTRIBUTION",
        help="simulate removal of a distribution name; repeat to remove a set",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="also verify non-shared declared files (all supported hashes/sizes)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--max-hash-bytes",
        type=_positive,
        default=Limits().max_hash_bytes,
        metavar="BYTES",
        help="total file-read budget (default: 536870912)",
    )
    args = parser.parse_args(argv)
    try:
        report = scan(
            args.site_packages,
            removing=args.removing,
            verify=args.verify,
            limits=Limits(max_hash_bytes=args.max_hash_bytes),
        )
    except (ScanError, ValueError) as error:
        if args.format == "json":
            print(json.dumps({"format_version": 1, "error": str(error)}, ensure_ascii=True))
        else:
            print(f"site-claims: {_quote(str(error))}", file=sys.stderr)
        return 2
    try:
        print(
            json.dumps(report, indent=2, ensure_ascii=True)
            if args.format == "json"
            else _text(report)
        )
    except BrokenPipeError:
        return 2
    return 1 if report["has_findings"] else 0
