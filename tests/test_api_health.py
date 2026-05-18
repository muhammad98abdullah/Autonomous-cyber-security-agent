import importlib
import os
import tempfile
import unittest

from fastapi.testclient import TestClient


class ApiHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["ASTRA_DB_PATH"] = os.path.join(self.tmp.name, "astra-test.db")
        import app.db
        import app.api.routes
        import main

        importlib.reload(app.db)
        importlib.reload(app.api.routes)
        importlib.reload(main)
        self.client = TestClient(main.app)

    def tearDown(self):
        self.tmp.cleanup()

    def test_health_ok_after_site_create(self):
        created = self.client.post("/v1/sites", json={"name": "Demo", "domain": "example.com"}).json()
        site_id = created["site"]["id"]
        token = created["dashboardToken"]

        health = self.client.get(
            f"/v1/sites/{site_id}/health",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")

    def test_health_danger_after_high_event(self):
        created = self.client.post("/v1/sites", json={"name": "Demo", "domain": "example.com"}).json()
        site_id = created["site"]["id"]
        dashboard_token = created["dashboardToken"]
        enrolled = self.client.post(
            "/v1/agents/enroll",
            json={
                "siteId": site_id,
                "enrollToken": created["enrollmentToken"],
                "hostname": "test-host",
            },
        ).json()

        self.client.post(
            "/v1/agents/events",
            json={
                "siteId": site_id,
                "agentToken": enrolled["agentToken"],
                "events": [
                    {
                        "attackType": "web_scan",
                        "severity": "high",
                        "sourceIp": "8.8.8.8",
                        "path": "/.env",
                        "ruleId": "suspicious_path",
                    }
                ],
            },
        )

        health = self.client.get(
            f"/v1/sites/{site_id}/health",
            headers={"Authorization": f"Bearer {dashboard_token}"},
        ).json()

        self.assertEqual(health["status"], "danger")
        self.assertEqual(health["lastDanger"]["attackType"], "web_scan")


if __name__ == "__main__":
    unittest.main()
