from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from site_claims.cli import main


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(list(args))
        return code, output.getvalue(), errors.getvalue()

    def fixture(self, root):
        info = root / "alpha-1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text("Name: alpha\nVersion: 1.0\n", encoding="utf-8")
        (info / "RECORD").write_text("file.py,,\n", encoding="utf-8")
        (root / "file.py").write_text("# original fixture\n", encoding="utf-8")
        return info

    def test_json_clean_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            code, out, err = self.invoke(directory, "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertFalse(json.loads(out)["has_findings"])

    def test_findings_exit_one_and_safe_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = self.fixture(root)
            (info / "RECORD").write_text('"bad\x1bpath",,\n', encoding="utf-8")
            code, out, _ = self.invoke(directory)
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", out)
        self.assertIn("INCOMPLETE", out)

    def test_json_operational_error(self):
        with tempfile.TemporaryDirectory() as directory:
            code, out, err = self.invoke(directory, "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))
        self.assertEqual(err, "")

    def test_text_operational_error(self):
        with tempfile.TemporaryDirectory() as directory:
            code, out, err = self.invoke(directory)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("site-claims:", err)

    def test_invalid_budget_is_argument_error(self):
        with (
            self.assertRaises(SystemExit) as error,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            main(["unused", "--max-hash-bytes", "0"])
        self.assertEqual(error.exception.code, 2)

    def test_module_cli_and_unexecuted_pth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            marker = root / "must-not-exist"
            (root / "untrusted.pth").write_text(
                f"import pathlib; pathlib.Path({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            env = {
                key: value
                for key, value in os.environ.items()
                if key not in {"PYTHONPATH", "PYTHONHOME"}
            }
            result = subprocess.run(
                [sys.executable, "-m", "site_claims", directory, "--format", "json"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(result.stdout)["summary"]["distributions"], 1)


if __name__ == "__main__":
    unittest.main()
