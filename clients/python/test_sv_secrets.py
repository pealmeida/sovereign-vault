"""Regression tests for the sv-secrets command-line output policy."""

from __future__ import annotations

import importlib.util
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "sv_secrets", Path(__file__).with_name("sv_secrets.py")
)
assert SPEC and SPEC.loader
sv_secrets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sv_secrets)


class SecretsCliOutputTests(unittest.TestCase):
    def test_cli_refuses_to_write_secret_values_to_stdout(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(sv_secrets, "load_secrets") as load_secrets,
            patch.object(sv_secrets.sys, "stdout", stdout),
            patch.object(sv_secrets.sys, "stderr", stderr),
        ):
            status = sv_secrets._main(["--container", "example"])

        self.assertEqual(status, 2)
        load_secrets.assert_not_called()
        self.assertNotIn("top-secret", stdout.getvalue())
        self.assertNotIn("top-secret", stderr.getvalue())

    def test_cli_writes_values_only_to_private_output_file(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / ".env.runtime"
            with (
                patch.object(
                    sv_secrets,
                    "load_secrets",
                    return_value=("env", {"API_TOKEN": "top-secret"}),
                ),
                patch.object(sv_secrets.sys, "stdout", stdout),
                patch.object(sv_secrets.sys, "stderr", stderr),
            ):
                status = sv_secrets._main(
                    ["--container", "example", "--out", str(output)]
                )

            self.assertEqual(status, 0)
            self.assertEqual(output.read_text("utf-8"), "API_TOKEN=top-secret\n")
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("top-secret", stderr.getvalue())

    def test_cli_atomically_replaces_output_with_0600_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / ".env.runtime"
            output.write_text("PREVIOUS=stale\n", encoding="utf-8")
            old_inode = output.stat().st_ino
            os.chmod(output, 0o644)

            with patch.object(
                sv_secrets,
                "load_secrets",
                return_value=("env", {"API_TOKEN": "top-secret"}),
            ):
                status = sv_secrets._main(
                    ["--container", "example", "--out", str(output)]
                )

            self.assertEqual(status, 0)
            self.assertEqual(output.read_text("utf-8"), "API_TOKEN=top-secret\n")
            self.assertNotEqual(output.stat().st_ino, old_inode)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_cli_failure_does_not_create_output_or_leak_secret(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / ".env.runtime"
            with (
                patch.object(
                    sv_secrets,
                    "load_secrets",
                    side_effect=RuntimeError("API_TOKEN=top-secret"),
                ),
                patch.object(sv_secrets.sys, "stdout", stdout),
                patch.object(sv_secrets.sys, "stderr", stderr),
            ):
                status = sv_secrets._main(
                    ["--container", "example", "--out", str(output)]
                )

            self.assertEqual(status, 1)
            self.assertFalse(output.exists())
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("top-secret", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
