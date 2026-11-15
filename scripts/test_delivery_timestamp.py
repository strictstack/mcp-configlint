"""Focused delivery checks using synthetic timestamps only."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

from verify_delivery import is_strict_utc_timestamp


class ReceiptTimestampTests(unittest.TestCase):
    def test_valid_utc_z_timestamps(self):
        for value in (
            "2026-11-13T11:22:38.450610Z",
            "2026-11-13T11:22:38Z",
            "2026-11-13T11:22:38.1Z",
            "2024-02-29T23:59:59.999999Z",
            "2000-02-29T00:00:00Z",
            "0001-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ):
            with self.subTest(value=value):
                self.assertTrue(is_strict_utc_timestamp(value))

    def test_rejects_offsets_and_noncanonical_formats(self):
        for value in (
            "2026-11-13T11:22:38.450610+00:00",
            "2026-11-13T11:22:38+01:00",
            "2026-11-13T11:22:38-00:00",
            "2026-11-13T11:22:38+00:00Z",
            "2026-11-13T11:22:38",
            "2026-11-13T11:22:38z",
            "2026-11-13t11:22:38Z",
            "2026-11-13 11:22:38Z",
            "2026-11-13T11:22Z",
            "2026-11-13",
            "20261113T112238Z",
            "2026-11-13T11:22:38,1Z",
            "2026-11-13T11:22:38.Z",
            "2026-11-13T11:22:38.1234567Z",
            "2026-1-3T01:02:03Z",
            " 2026-11-13T11:22:38Z",
            "2026-11-13T11:22:38Z ",
            "2026-11-13T11:22:38Z\n",
            "２０２６-11-13T11:22:38Z",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_strict_utc_timestamp(value))

    def test_rejects_impossible_dates_and_times(self):
        for value in (
            "0000-01-01T00:00:00Z",
            "2026-00-13T11:22:38Z",
            "2026-13-13T11:22:38Z",
            "2026-11-00T11:22:38Z",
            "2026-11-31T11:22:38Z",
            "2026-02-29T11:22:38Z",
            "1900-02-29T11:22:38Z",
            "2024-02-30T11:22:38Z",
            "2026-11-13T24:00:00Z",
            "2026-11-13T11:60:38Z",
            "2026-11-13T11:22:60Z",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_strict_utc_timestamp(value))

    def test_rejects_missing_or_wrong_types(self):
        for value in (None, "", 0, 1234567890, 1.5, True, [], {},
                      b"2026-11-13T11:22:38Z"):
            with self.subTest(value=value):
                self.assertFalse(is_strict_utc_timestamp(value))

    def test_import_does_not_read_delivery_artifacts_or_invoke_git(self):
        output = io.StringIO()
        with patch.object(Path, "read_text", side_effect=AssertionError("artifact read")), \
                patch("subprocess.check_output", side_effect=AssertionError("git invoked")), \
                redirect_stdout(output):
            namespace = runpy.run_path(
                str(Path(__file__).with_name("verify_delivery.py")),
                run_name="delivery_timestamp_import_test",
            )
        self.assertTrue(callable(namespace["is_strict_utc_timestamp"]))
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()

