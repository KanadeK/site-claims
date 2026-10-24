# Design and acceptance

## The question

Which distributions declare the same installed file, what does that file contain
now, and which still-present distribution shares a path with a proposed removal
set? The input is an explicit directory, not a Python interpreter or requirement
list. The unit of ownership is an installed RECORD path, not a top-level import
name. We do not infer which distribution is desirable or trustworthy.

## Implementation

1. Enumerate only immediate `.dist-info` / `.egg-info` entries under the root.
2. Read bounded `METADATA` headers; use directory IDs to distinguish claimants and
   normalized distribution names to select a removal set. Invalid metadata and
   legacy metadata remain visible as issues.
3. Parse bounded UTF-8 CSV RECORDs. Canonicalize lexical relative paths. Detect
   duplicate rows and duplicate normalized distribution names. External, absolute,
   control-character, and unsupported platform paths are listed without opening.
4. Build a map from native comparison key to all claims. Directory prefixes are
   not claims. Windows keys use `normcase`; POSIX keys retain exact spelling.
5. Read shared paths once (all paths with `--verify`). Compute needed SHA-256,
   SHA-384 and SHA-512 digests in one bounded streaming pass. Before opening, check
   every in-root component for symlinks/reparse points and the final regular-file
   type; compare the opened file's identity. Reject observed size/mtime changes.
6. Report hash agreement, per-claim disk matches, missing/unreadable files, and
   shared paths with both a removed claimant and a remaining claimant.

No subprocess, importlib discovery, pip internals, `.pth` processing, plugin,
network client, writer or installer is used by the scanner. The standalone demo
uses subprocesses only for its own disposable fixture venv.

Total graph/manifest limits abort with ScanError instead of emitting a partial
graph. Per-metadata failures remain visible with incomplete coverage. File-read
limits leave a `hash_limit` state and incomplete coverage. Python CSV's own field
limit also applies; a field rejected by it is a visible unreadable RECORD.

Work is O(manifest bytes + declared paths log declared paths + bytes actually read).
Memory is bounded by manifests/rows and the graph, rather than file payload size.

## JSON v1

- `distributions`: id, original name, normalized name, version.
- `collisions`: path, `agreement` (`identical`/`different`/`unknown`), disk state,
  and all claims with hash, size, `matches_disk`, `size_matches_disk`.
- `removal_risks`: path, removed and remaining claimant IDs, observed disk state.
- `file_findings`: checked files that are missing, unreadable, over budget, changed
  during reading, or do not match one or more declared hashes/sizes.
- `metadata_issues` / `excluded_claims`: evidence that the graph has limitations.
- `summary`: counts, unhashed claims and actual hash-read byte consumption.
- `verification`: `shared` or `all`. `coverage_complete` describes graph/read
  coverage in this scope, not authenticity or all-payload hash verification.
- `has_findings`: controls exit 1; any collision, file finding, issue or exclusion.

The report is deterministic for a stable directory. Input order does not decide
which claimant wins. Equal supported hashes establish declared agreement, not
trust. Different hash algorithms remain `unknown` unless sizes already disagree.
Missing hashes and missing on-disk files never become successful hash matches.

## Acceptance and limits

The real-install test builds original local wheels, installs them sequentially
with pip in a disposable venv, observes pip check succeeding, diagnoses divergent
shared source and current matching claimant, models uninstall impact, actually
uninstalls a fixture and detects the surviving claimant's missing source file.
Other tests cover identical-byte risk, removal sets, valid namespace sharing,
malformed inputs and resource/file boundaries. No test substitutes a canned pip
result or disables the scanner's core logic.

This is not an OS sandbox. Parent-directory races, dishonest RECORDs, import-path
shadowing across roots, POSIX case aliases, generated-file inference and external
editable source remain outside its guarantee. See README for all default limits.
No automatic mutation is planned for this version.
