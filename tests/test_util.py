from __future__ import annotations

import unittest

from sklab.util import parse_scalar, powershell_command, redact


class UtilTests(unittest.TestCase):
    def test_powershell_command_quotes_the_executable_and_arguments(self) -> None:
        self.assertEqual(
            powershell_command(
                [
                    r"C:\Program Files\WindowsApps\WinDbgX.exe",
                    "-k",
                    r"com:pipe,port=\\.\pipe\a'b,resets=0",
                ]
            ),
            r"& 'C:\Program Files\WindowsApps\WinDbgX.exe' '-k' "
            r"'com:pipe,port=\\.\pipe\a''b,resets=0'",
        )

    def test_parse_scalar_supports_console_values(self) -> None:
        self.assertEqual(parse_scalar("0x2a"), 42)
        self.assertIs(parse_scalar("yes"), True)
        self.assertIs(parse_scalar("off"), False)
        self.assertIsNone(parse_scalar("null"))
        self.assertEqual(parse_scalar("KiTimerInterrupt"), "KiTimerInterrupt")

    def test_redact_removes_named_secrets_and_kd_keys(self) -> None:
        value = redact({"password": "nope", "connection": "net:port=50000,key=1.2.3.4"})
        self.assertEqual(value["password"], "<redacted>")
        self.assertEqual(value["connection"], "net:port=50000,key=<redacted>")


if __name__ == "__main__":
    unittest.main()
