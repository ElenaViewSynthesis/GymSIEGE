from __future__ import annotations

import argparse
import unittest

from modal_snapshot_ceiling_probe import GB, fill_script, parse_size_gb


class ModalSnapshotCeilingProbeTests(unittest.TestCase):
    def test_parse_size_gb_uses_decimal_gigabytes(self) -> None:
        self.assertEqual(parse_size_gb("265"), 265 * GB)
        self.assertEqual(parse_size_gb("1.5"), 1_500_000_000)

    def test_parse_size_gb_rejects_nonpositive_values(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_size_gb("0")

    def test_fill_script_uses_exact_target_and_optional_inode_fill(self) -> None:
        byte_only = fill_script(123_000_000_000, None)
        self.assertIn("target=123000000000", byte_only)
        self.assertNotIn("snapshot-probe-inodes", byte_only)

        inode_probe = fill_script(30_000_000_000, 3_100_000)
        self.assertIn("target = 3100000", inode_probe)
        self.assertIn("snapshot-probe-inodes", inode_probe)


if __name__ == "__main__":
    unittest.main()
