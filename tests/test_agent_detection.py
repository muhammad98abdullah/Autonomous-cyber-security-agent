import unittest

from astra_agent import Detector, parse_log_line


class AgentDetectionTests(unittest.TestCase):
    def test_parse_nginx_access_line(self):
        line = '8.8.8.8 - - [18/May/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8"'
        record = parse_log_line("/var/log/nginx/access.log", line)

        self.assertEqual(record["sourceIp"], "8.8.8.8")
        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["path"], "/.env")
        self.assertEqual(record["statusCode"], 404)

    def test_suspicious_path_creates_high_event(self):
        detector = Detector()
        record = {
            "sourceIp": "8.8.8.8",
            "method": "GET",
            "path": "/.env",
            "statusCode": 404,
            "userAgent": "curl",
            "raw": "sample",
        }

        event = detector.inspect(record)

        self.assertEqual(event["attackType"], "sensitive_file_scan")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["ruleId"], "sensitive_path_scan")

    def test_repeated_login_creates_brute_force_event(self):
        detector = Detector()
        event = None
        for _ in range(8):
            event = detector.inspect(
                {
                    "sourceIp": "8.8.8.8",
                    "method": "POST",
                    "path": "/wp-login.php",
                    "statusCode": 403,
                    "userAgent": "curl",
                    "raw": "sample",
                }
            )

        self.assertEqual(event["attackType"], "brute_force")
        self.assertEqual(event["ruleId"], "repeated_login_attempts")

    def test_request_flood_creates_dos_event(self):
        detector = Detector()
        event = None
        for _ in range(120):
            event = detector.inspect(
                {
                    "sourceIp": "8.8.8.8",
                    "method": "GET",
                    "path": "/",
                    "statusCode": 200,
                    "userAgent": "curl",
                    "raw": "sample",
                }
            )

        self.assertEqual(event["attackType"], "dos_http_flood")
        self.assertEqual(event["ruleId"], "single_ip_flood")

    def test_normal_request_returns_no_event(self):
        detector = Detector()
        record = {
            "sourceIp": "8.8.8.8",
            "method": "GET",
            "path": "/",
            "statusCode": 200,
            "userAgent": "browser",
            "raw": "sample",
        }

        self.assertIsNone(detector.inspect(record))


if __name__ == "__main__":
    unittest.main()
