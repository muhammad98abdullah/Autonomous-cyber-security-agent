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
            "path": "/wp-login.php",
            "statusCode": 404,
            "userAgent": "curl",
            "raw": "sample",
        }

        event = detector.inspect(record)

        self.assertEqual(event["attackType"], "web_scan")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["ruleId"], "suspicious_path")

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
