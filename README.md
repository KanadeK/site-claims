# site-claims

Explain which installed Python distributions claim the same files, whose RECORD
matches the bytes on disk, and which remaining package may lose a file if you
uninstall a chosen distribution.

[中文说明](README.zh-CN.md) · [Design and report format](docs/DESIGN.md) ·
[Security](SECURITY.md) · MIT · Python 3.10+ · No runtime dependencies

`pip check` can pass while two differently named packages overwrite the same
module. Uninstalling either can then remove a file the other still needs. This is
a [documented pip issue](https://github.com/pypa/pip/issues/4625).

site-claims reads an **explicit site-packages directory** without starting its
interpreter, importing its packages, or executing its `.pth` files. It works with
an offline copy, too. It never installs, repairs, or deletes anything.

## Install

Use a trusted Python installation and keep this tool in its own virtual environment.
Do not launch a suspected environment's Python just to inspect it.

```sh
git clone https://github.com/KanadeK/site-claims.git
cd site-claims
python -m venv .venv-tools
```

Linux/macOS:

```sh
.venv-tools/bin/python -m pip install .
.venv-tools/bin/python -I -m site_claims --version
```

Windows PowerShell:

```powershell
.venv-tools\Scripts\python.exe -m pip install .
.venv-tools\Scripts\python.exe -I -m site_claims --version
```

Alternatively, download `site_claims-0.1.0-py3-none-any.whl` and `SHA256SUMS` from
[Releases](https://github.com/KanadeK/site-claims/releases). Verify the downloaded
wheel against SHA256SUMS, then run your tool environment's Python with
`-m pip install --no-index --no-deps path/to/site_claims-0.1.0-py3-none-any.whl`.
The checksums detect download corruption; they are not an independent signature.
No PyPI publication is claimed.

## Diagnose a target environment

The commands below assume the tool environment is activated (`site-claims` is also
available as `python -I -m site_claims`). Supply the target's **library directory**,
not its venv root. For example:

```sh
site-claims target-venv/lib/python3.13/site-packages
site-claims target-venv/lib/python3.13/site-packages --removing example-beta --format json
site-claims target-venv/lib/python3.13/site-packages --verify --format json
```

Windows targets commonly use `target-venv\Lib\site-packages` instead. The target's
Python version can differ from the tool's; this command reads files only.

- A shared file is reported even if both distributions declare identical bytes:
  their uninstall file lists still overlap.
- `agreement` is `identical`, `different`, or `unknown`, based on declared hashes
  and sizes. `matches_disk` compares each supported declared hash to current bytes.
- Shared namespace **directories** with distinct files are allowed. An actual
  shared `namespace/__init__.py` remains a shared file.
- Repeat `--removing` to model a set. Only paths also claimed by distributions
  outside that set appear in `removal_risks`. This does not run pip or predict
  installer-specific behavior with certainty.
- By default only shared paths are read and hashed. `--verify` also checks unique
  declared paths for missing files, changed bytes, and incorrect sizes.

The report uses distribution directory IDs such as `example_beta-1.0.dist-info` to
distinguish claimants. Removal arguments use their `METADATA` names, normalized
case-insensitively with `.`, `_`, and `-` treated as equivalent.

## Try the complete failure and diagnosis locally

After installing the tool, run:

```sh
python examples/demo.py
```

This creates a disposable venv and two original synthetic wheels, installs them
with pip entirely offline, checks the conflicting file, simulates removal, then
actually uninstalls the second fixture and verifies the first fixture's file is
missing. The venv and fixtures are cleaned up automatically. It neither downloads
nor uninstalls a real third-party package.

Expected fields in its actual generated result:

```json
{
  "pip_check": "No broken requirements found.",
  "shared_path": "shared_demo/__init__.py",
  "expected": "different",
  "current_match": "claims-demo-beta",
  "remaining_at_risk": "claims-demo-alpha",
  "after_real_uninstall": "missing",
  "target_cleaned": true
}
```

The real environment can also share generated `.pyc` files; the demo checks the
source file explicitly rather than assuming a fixed count of all shared files.

## Exit codes and coverage

| Code | Meaning |
|---|---|
| 0 | No findings in the declared scan scope |
| 1 | Shared files, file mismatches, metadata problems, or excluded claims need review |
| 2 | Invocation, directory, unknown removal name, or total resource-limit failure |

Exit 1 is diagnostic, not a malware verdict. Normal entry point scripts often have
RECORD paths outside site-packages; these are listed as excluded and yield exit 1.
They are **never opened**, even when `--verify` is used. A report with excluded
claims or unreadable metadata is marked `coverage_complete: false`.

`coverage_complete` means the declared graph was readable within this limited
scope. It does not mean all file contents were hashed. Unhashed entries (normally
RECORD itself and generated bytecode) remain explicitly unknown. Exit 0 does not
establish package authenticity, runtime import behavior, or absence of undeclared
files.

JSON uses `format_version: 1`; paths are relative, and text output escapes input
control characters. With `--format json`, scan failures produce an `error` object
and exit 2. Argument syntax errors use argparse's stderr output.

## Limits in v0.1.0

- One library root at a time; no wheel preflight, dependency resolver, automatic
  repair, or uninstall command. RECORD claims may be stale or dishonest.
- No external/absolute paths, legacy `.egg-info`, linked files, junctions/reparse
  points, or nonregular files are read. Editable source outside this root and
  undeclared/generated import files are outside the graph.
- SHA-256/384/512 are supported. Blank hashes are allowed; other algorithms produce
  a visible metadata issue. Different hash algorithms do not prove equal content.
- Windows uses `normcase`; POSIX uses exact spelling, including on macOS. A
  case-insensitive POSIX volume may have aliases the graph does not combine.
- Inspect a quiescent directory or snapshot. Link checks, regular-file checks and
  file identity checks reduce accidental traversal; they are not an OS sandbox
  against hostile concurrent filesystem replacement. No network or target-code
  execution is used by the scanner.
- Default caps: 5,000 distributions, 100,000 root entries, 200,000 RECORD rows,
  1 MiB per METADATA, 16 MiB per RECORD, 64 MiB total manifest bytes, 4,096 characters
  per path, and 512 MiB of file reads. Adjust the last with `--max-hash-bytes BYTES`;
  other bounds are available through the Python `Limits` API. Limits produce a
  marked incomplete report or abort, never a falsely complete partial graph.

If a collision matters, recreate the target venv from reviewed dependencies and
resolve the conflicting distribution choices there. Preserve the original for
diagnosis. site-claims does not decide which package should win.

## Develop and clean up

```sh
python -m pip install .
python -m unittest discover -s tests -v
python examples/demo.py
python -m pip install ruff==0.14.10
ruff check .
ruff format --check .
```

Tests include a real pip lifecycle, namespace coexistence, identical-file removal
risk, corrupt/missing metadata, resource limits, byte drift, terminal controls,
and platform file boundaries. See [CI](https://github.com/KanadeK/site-claims/actions)
for the executed OS/version matrix. Conditional tests explain platform skips.

Uninstall using the **tool environment's** Python: `python -m pip uninstall site-claims`.
When no longer needed, remove the tool venv and source checkout with your file
manager. Scans create no cache or state in the target. Shell-redirection reports
you created can be removed separately.

## Existing tools

[pip check](https://pip.pypa.io/en/stable/cli/pip_check/) checks dependency compatibility.
[ModuleGuard](https://github.com/ZJU-SEC/ModuleGuard) studies module namespace conflicts
through source/install simulation and dependency resolution.
[check-wheel-contents](https://github.com/jwodder/check-wheel-contents) checks individual
wheel contents. The open pip [overwrite-warning PR](https://github.com/pypa/pip/pull/14249)
addresses install-time warnings. site-claims focuses on an already installed
directory, exact shared claims, present-byte attribution, and removal-set impact.
These projects are useful alternatives, not sources of this implementation.
