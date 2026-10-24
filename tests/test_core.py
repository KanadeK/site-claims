from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from site_claims import Limits, ScanError, scan
from site_claims.core import _digest, _record_path, normalize_name


def hashed(content: bytes, algorithm="sha256") -> str:
    digest = hashlib.new(algorithm, content).digest()
    return algorithm + "=" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "library"
        self.root.mkdir()

    def dist(self, name="alpha", rows=None, metadata=None, directory=None):
        info = self.root / (directory or f"{name}-1.0.dist-info")
        info.mkdir()
        (info / "METADATA").write_text(
            metadata or f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n\n",
            encoding="utf-8",
        )
        text = io.StringIO(newline="")
        writer = csv.writer(text, lineterminator="\n")
        writer.writerows(rows or [[f"{info.name}/RECORD", "", ""]])
        (info / "RECORD").write_text(text.getvalue(), encoding="utf-8")
        return info

    def file(self, name="shared.py", data=b"alpha\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def pair(self, first=b"alpha\n", second=b"beta\n", disk=None, path="shared.py"):
        self.file(path, second if disk is None else disk)
        self.dist("alpha", [[path, hashed(first), len(first)]])
        self.dist("beta", [[path, hashed(second), len(second)]])

    def test_normalize_distribution_name(self):
        self.assertEqual(normalize_name("Some_Name.X--Y"), "some-name-x-y")

    def test_single_distribution_is_clean(self):
        self.file()
        self.dist(rows=[["shared.py", hashed(b"alpha\n"), 6]])
        report = scan(self.root, verify=True)
        self.assertFalse(report["has_findings"])
        self.assertTrue(report["coverage_complete"])

    def test_shared_different_hashes_and_current_owner(self):
        self.pair()
        report = scan(self.root)
        collision = report["collisions"][0]
        self.assertEqual(collision["agreement"], "different")
        self.assertEqual([c["matches_disk"] for c in collision["claims"]], [False, True])
        self.assertEqual(report["summary"]["hash_bytes_read"], 5)

    def test_identical_bytes_still_have_removal_risk(self):
        self.pair(first=b"same", second=b"same")
        report = scan(self.root, removing=["alpha"])
        self.assertEqual(report["collisions"][0]["agreement"], "identical")
        self.assertEqual(report["removal_risks"][0]["remaining"], ["beta-1.0.dist-info"])
        self.assertTrue(report["has_findings"])

    def test_removing_all_claimants_has_no_remaining_risk(self):
        self.pair()
        report = scan(self.root, removing=["alpha", "beta", "ALPHA"])
        self.assertEqual(report["removal_risks"], [])
        self.assertEqual(report["removing"], ["alpha", "beta"])
        self.assertEqual(len(report["collisions"]), 1)

    def test_unknown_removal_fails(self):
        self.dist()
        with self.assertRaisesRegex(ScanError, "not found"):
            scan(self.root, removing=["absent"])

    def test_removal_name_normalization(self):
        self.file()
        self.dist("my_package", [["shared.py", "", ""]])
        self.dist("beta", [["shared.py", "", ""]])
        self.assertEqual(len(scan(self.root, removing=["MY.PACKAGE"])["removal_risks"]), 1)

    def test_namespace_directory_is_not_shared_file(self):
        self.file("space/alpha.py", b"a")
        self.file("space/beta.py", b"b")
        self.dist("alpha", [["space/alpha.py", hashed(b"a"), 1]])
        self.dist("beta", [["space/beta.py", hashed(b"b"), 1]])
        self.assertFalse(scan(self.root, verify=True)["has_findings"])

    def test_unknown_hashes_remain_unknown(self):
        self.file()
        self.dist("alpha", [["shared.py", "", ""]])
        self.dist("beta", [["shared.py", "", ""]])
        report = scan(self.root)
        self.assertEqual(report["collisions"][0]["agreement"], "unknown")
        self.assertIsNone(report["collisions"][0]["claims"][0]["matches_disk"])
        self.assertEqual(report["summary"]["unhashed_claims"], 2)

    def test_cross_algorithm_matches_are_verified_separately(self):
        self.file(data=b"same")
        self.dist("alpha", [["shared.py", hashed(b"same"), 4]])
        self.dist("beta", [["shared.py", hashed(b"same", "sha512"), 4]])
        collision = scan(self.root)["collisions"][0]
        self.assertEqual(collision["agreement"], "unknown")
        self.assertTrue(all(item["matches_disk"] for item in collision["claims"]))

    def test_conflicting_sizes_are_different(self):
        self.file()
        self.dist("alpha", [["shared.py", "", "6"]])
        self.dist("beta", [["shared.py", "", "7"]])
        collision = scan(self.root)["collisions"][0]
        self.assertEqual(collision["agreement"], "different")
        self.assertFalse(collision["claims"][1]["size_matches_disk"])

    def test_missing_shared_file(self):
        self.pair()
        (self.root / "shared.py").unlink()
        self.assertEqual(scan(self.root)["collisions"][0]["disk"]["state"], "missing")

    def test_verify_finds_unique_file_drift(self):
        self.file(data=b"new")
        self.dist(rows=[["shared.py", hashed(b"old"), 3]])
        self.assertFalse(scan(self.root)["has_findings"])
        self.assertEqual(len(scan(self.root, verify=True)["file_findings"]), 1)

    def test_verify_finds_unique_file_missing(self):
        self.dist(rows=[["missing.py", hashed(b"old"), 3]])
        report = scan(self.root, verify=True)
        self.assertEqual(report["file_findings"][0]["disk"]["state"], "missing")

    def test_size_mismatch_without_hash(self):
        self.file(data=b"short")
        self.dist(rows=[["shared.py", "", "999"]])
        self.assertFalse(
            scan(self.root, verify=True)["file_findings"][0]["claims"][0]["size_matches_disk"]
        )

    def test_csv_quoted_comma_and_unicode_path(self):
        self.file("données,ok.py", b"data")
        self.dist(rows=[["données,ok.py", hashed(b"data"), 4]])
        self.assertFalse(scan(self.root, verify=True)["has_findings"])

    def test_lexical_path_aliases_are_one_claim(self):
        self.file()
        self.dist(rows=[["./shared.py", "", ""], ["x/../shared.py", "", ""]])
        report = scan(self.root)
        self.assertEqual(report["summary"]["claimed_paths"], 1)
        self.assertEqual(report["metadata_issues"][0]["code"], "duplicate_record_path")

    def test_external_paths_are_not_opened(self):
        self.dist(
            rows=[
                ["../outside.txt", hashed(b"private"), 7],
                ["/absolute/outside", "", ""],
                ["C:/outside.txt", "", ""],
            ]
        )
        report = scan(self.root, verify=True)
        self.assertEqual(len(report["excluded_claims"]), 3)
        self.assertEqual(report["summary"]["hash_bytes_read"], 0)
        self.assertFalse(report["coverage_complete"])

    def test_control_path_is_rejected(self):
        self.dist(rows=[["bad\x1bname.py", "", ""]])
        report = scan(self.root)
        self.assertEqual(report["excluded_claims"][0]["reason"], "invalid_path")

    def test_invalid_record_row(self):
        info = self.dist()
        (info / "RECORD").write_text("only-two,fields\n", encoding="utf-8")
        self.assertTrue(
            any(item["code"] == "invalid_record" for item in scan(self.root)["metadata_issues"])
        )

    def test_malformed_csv_is_visible(self):
        info = self.dist()
        (info / "RECORD").write_text('"unterminated,hash,1', encoding="utf-8")
        self.assertFalse(scan(self.root)["coverage_complete"])

    def test_invalid_utf8_record_is_visible(self):
        info = self.dist()
        (info / "RECORD").write_bytes(b"\xff")
        self.assertEqual(scan(self.root)["metadata_issues"][0]["code"], "record_unreadable")

    def test_missing_record_is_visible(self):
        info = self.dist()
        (info / "RECORD").unlink()
        self.assertFalse(scan(self.root)["coverage_complete"])

    def test_duplicate_metadata_headers_rejected(self):
        self.dist(metadata="Name: alpha\nName: beta\nVersion: 1.0\n")
        self.assertEqual(scan(self.root)["distributions"], [])

    def test_invalid_distribution_name_rejected(self):
        self.dist(metadata="Name: bad name\nVersion: 1.0\n")
        self.assertFalse(scan(self.root)["coverage_complete"])

    def test_duplicate_normalized_distributions(self):
        self.dist("my-pkg")
        self.dist("my_pkg")
        self.assertTrue(
            any(
                item["code"] == "duplicate_distribution"
                for item in scan(self.root)["metadata_issues"]
            )
        )

    def test_legacy_metadata_is_visible(self):
        (self.root / "old.egg-info").mkdir()
        report = scan(self.root)
        self.assertEqual(report["metadata_issues"][0]["code"], "legacy_metadata")

    def test_no_metadata_is_error(self):
        with self.assertRaisesRegex(ScanError, "no .dist-info"):
            scan(self.root)

    def test_root_not_directory_is_error(self):
        file = self.file()
        with self.assertRaises(ScanError):
            scan(file)

    def test_hash_algorithms_and_invalid_hashes(self):
        for algorithm in ("sha256", "sha384", "sha512"):
            self.assertEqual(_digest(hashed(b"abc", algorithm))[0], algorithm)
        for value in ("md5=abc", "sha256=abc", "sha256=???", "sha256=", "no-separator"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _digest(value)

    def test_invalid_hash_and_size_are_reported(self):
        self.file()
        self.dist(rows=[["shared.py", "sha256=bad", "-1"]])
        self.assertTrue(scan(self.root, verify=True)["metadata_issues"])

    def test_oversized_fields_are_not_retained(self):
        self.file()
        self.dist(rows=[["shared.py", "x" * 1000, "9" * 50]])
        report = scan(self.root, verify=True)
        self.assertTrue(report["metadata_issues"])
        self.assertEqual(report["summary"]["unhashed_claims"], 1)

    def test_hash_budget_marks_incomplete(self):
        self.pair()
        report = scan(self.root, limits=Limits(max_hash_bytes=1))
        self.assertEqual(report["collisions"][0]["disk"]["state"], "hash_limit")
        self.assertFalse(report["coverage_complete"])

    def test_hash_budget_is_total_not_per_file(self):
        self.file("a.py", b"abc")
        self.file("b.py", b"def")
        self.dist(rows=[["a.py", hashed(b"abc"), 3], ["b.py", hashed(b"def"), 3]])
        report = scan(self.root, verify=True, limits=Limits(max_hash_bytes=4))
        self.assertEqual(report["file_findings"][0]["path"], "b.py")
        self.assertEqual(report["summary"]["hash_bytes_read"], 3)

    def test_total_row_limit_aborts(self):
        self.dist(rows=[["a", "", ""], ["b", "", ""]])
        with self.assertRaisesRegex(ScanError, "row limit"):
            scan(self.root, limits=Limits(max_entries=1))

    def test_total_manifest_limit_aborts(self):
        self.dist()
        with self.assertRaisesRegex(ScanError, "manifest byte limit"):
            scan(self.root, limits=Limits(max_manifest_bytes=1))

    def test_distribution_and_root_entry_limits(self):
        self.dist()
        self.dist("beta")
        with self.assertRaisesRegex(ScanError, "distribution limit"):
            scan(self.root, limits=Limits(max_distributions=1))
        with self.assertRaisesRegex(ScanError, "root entry limit"):
            scan(self.root, limits=Limits(max_root_entries=1))

    def test_metadata_and_record_byte_limits(self):
        self.dist()
        self.assertFalse(scan(self.root, limits=Limits(max_metadata_bytes=1))["coverage_complete"])
        self.assertFalse(scan(self.root, limits=Limits(max_record_bytes=1))["coverage_complete"])

    def test_limits_validate_api_inputs(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                Limits(max_entries=value)

    def test_directory_claim_is_not_read_as_file(self):
        (self.root / "directory").mkdir()
        self.dist(rows=[["directory", "", ""]])
        report = scan(self.root, verify=True)
        self.assertEqual(report["file_findings"][0]["disk"]["state"], "unreadable")

    def test_scan_does_not_mutate_inputs(self):
        self.pair()
        before = {
            p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()
        }
        scan(self.root, verify=True, removing=["alpha"])
        after = {
            p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()
        }
        self.assertEqual(before, after)

    def test_deterministic_report(self):
        self.pair()
        self.assertEqual(scan(self.root), scan(self.root))

    def test_reparse_file_not_read(self):
        path = self.file()
        self.dist(rows=[["shared.py", hashed(b"alpha\n"), 6]])
        with patch("site_claims.core._linked", return_value=True):
            report = scan(self.root, verify=True)
        self.assertFalse(report["coverage_complete"])
        self.assertEqual(path.read_bytes(), b"alpha\n")

    def test_symlink_ancestor_does_not_read_outside(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "private.py").write_bytes(b"private")
        try:
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("host does not grant directory symlink creation")
        self.dist(rows=[["linked/private.py", hashed(b"private"), 7]])
        report = scan(self.root, verify=True)
        self.assertEqual(report["summary"]["hash_bytes_read"], 0)
        self.assertEqual(report["file_findings"][0]["disk"]["state"], "unreadable")

    def test_special_file_does_not_block(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("POSIX FIFO required")
        os.mkfifo(self.root / "pipe")
        self.dist(rows=[["pipe", "", ""]])
        self.assertEqual(
            scan(self.root, verify=True)["file_findings"][0]["disk"]["state"],
            "unreadable",
        )

    def test_platform_path_rules(self):
        if os.name == "nt":
            for path in (
                "NUL",
                "CON.txt",
                "name:stream",
                "LPT1.py",
                "COM².txt",
                "name.",
            ):
                with self.subTest(path=path):
                    self.assertEqual(_record_path(path)[1], "unsupported_path")
            self.assertEqual(_record_path("pkg\\module.py"), ("pkg/module.py", None))
        else:
            self.assertEqual(_record_path("pkg\\module.py")[1], "unsupported_path")
        self.assertEqual(_record_path("../outside")[1], "external_path")


if __name__ == "__main__":
    unittest.main()
