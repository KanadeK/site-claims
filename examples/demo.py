"""Offline reproduction with original synthetic wheels in a disposable venv.

Run after installing site-claims: python examples/demo.py
No real third-party distribution is installed, imported, or uninstalled.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from site_claims import scan


def make_wheel(directory: Path, name: str, value: str) -> Path:
    """Build a tiny valid pure wheel; fixture source is authored for this demo."""
    info = f"{name}-1.0.dist-info"
    files = {
        "shared_demo/__init__.py": f"OWNER = {value!r}\n".encode(),
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n\n".encode(),
        f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: site-claims-demo\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        writer.writerow([path, "sha256=" + digest, len(content)])
    writer.writerow([f"{info}/RECORD", "", ""])
    files[f"{info}/RECORD"] = record.getvalue().encode()
    wheel = directory / f"{name}-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return wheel


def demo() -> dict:
    def run(*args):
        result = subprocess.run(
            list(map(str, args)),
            cwd=temporary,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        return result.stdout.strip()

    with tempfile.TemporaryDirectory(prefix="site-claims-demo-") as directory:
        temporary = Path(directory)
        environment = temporary / "target"
        run(sys.executable, "-m", "venv", environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        library = Path(
            run(
                python,
                "-I",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            )
        )
        alpha = make_wheel(temporary, "claims_demo_alpha", "alpha")
        beta = make_wheel(temporary, "claims_demo_beta", "beta")
        run(python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", alpha)
        before = scan(library)
        assert before["summary"]["shared_paths"] == 0
        run(python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", beta)
        pip_check = run(python, "-I", "-m", "pip", "check")
        report = scan(library, removing=["claims-demo-beta"])
        collision = next(
            item for item in report["collisions"] if item["path"] == "shared_demo/__init__.py"
        )
        assert collision["agreement"] == "different"
        assert [item["owner"] for item in collision["claims"] if item["matches_disk"]] == [
            "claims_demo_beta-1.0.dist-info"
        ]
        assert any(item["path"] == collision["path"] for item in report["removal_risks"])
        run(python, "-I", "-m", "pip", "uninstall", "-y", "claims-demo-beta")
        after = scan(library, verify=True)
        missing = next(
            item for item in after["file_findings"] if item["path"] == "shared_demo/__init__.py"
        )
        assert missing["disk"]["state"] == "missing"
        assert not (library / "shared_demo/__init__.py").exists()
        return {
            "pip_check": pip_check,
            "shared_path": collision["path"],
            "expected": collision["agreement"],
            "current_match": "claims-demo-beta",
            "remaining_at_risk": "claims-demo-alpha",
            "after_real_uninstall": missing["disk"]["state"],
            "target_cleaned": True,
        }


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
