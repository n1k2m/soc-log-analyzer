import unittest

from parser_module import _parse_line


class ParserTests(unittest.TestCase):
    def test_valid_apache_line(self) -> None:
        parsed = _parse_line(
            '192.0.2.10 - - [10/Oct/2025:13:55:36 +0000] '
            '"POST /login HTTP/1.1" 401 128'
        )

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.ip, "192.0.2.10")
        self.assertEqual(parsed.method, "POST")
        self.assertEqual(parsed.url, "/login")
        self.assertEqual(parsed.status, "401")
        self.assertEqual(parsed.bytes, 128)

    def test_malformed_line_returns_none(self) -> None:
        self.assertIsNone(_parse_line("not an apache access log line"))

    def test_invalid_timestamp_returns_none(self) -> None:
        parsed = _parse_line(
            '192.0.2.10 - - [bad-time] "POST /login HTTP/1.1" 401 128'
        )

        self.assertIsNone(parsed)

    def test_optional_bytes_default_to_zero(self) -> None:
        parsed = _parse_line(
            '192.0.2.10 - - [10/Oct/2025:13:55:36 +0000] '
            '"GET / HTTP/1.1" 200'
        )

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.bytes, 0)

    def test_dash_bytes_default_to_zero(self) -> None:
        parsed = _parse_line(
            '192.0.2.10 - - [10/Oct/2025:13:55:36 +0000] '
            '"GET / HTTP/1.1" 200 -'
        )

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.bytes, 0)


if __name__ == "__main__":
    unittest.main()
