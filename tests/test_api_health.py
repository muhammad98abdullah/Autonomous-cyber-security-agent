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

    def test_site_create_uses_public_backend_url_for_installer(self):
        created = self.client.post(
            "/v1/sites",
            json={
                "name": "Demo",
                "domain": "example.com",
                "publicBackendUrl": "https://astra.example.com/api/",
            },
        ).json()

        self.assertEqual(created["installBackendUrl"], "https://astra.example.com/api")
        self.assertIn("https://astra.example.com/api/install.sh", created["installCommand"])
        self.assertIn("--backend-url https://astra.example.com/api", created["installCommand"])
        self.assertIsNone(created["installCommandWarning"])

    def test_site_create_warns_when_installer_uses_localhost(self):
        created = self.client.post(
            "/v1/sites",
            json={"name": "Demo", "domain": "example.com", "publicBackendUrl": "http://127.0.0.1:8000"},
        ).json()

        self.assertIn("localhost", created["installCommandWarning"])

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

    def test_allowlist_prevents_block_decision(self):
        created = self.client.post("/v1/sites", json={"name": "Demo", "domain": "example.com"}).json()
        site_id = created["site"]["id"]
        dashboard_token = created["dashboardToken"]
        enrolled = self.client.post(
            "/v1/agents/enroll",
            json={"siteId": site_id, "enrollToken": created["enrollmentToken"], "hostname": "test-host"},
        ).json()

        self.client.post(
            f"/v1/sites/{site_id}/allowlist",
            headers={"Authorization": f"Bearer {dashboard_token}"},
            json={"ip": "8.8.8.8", "label": "Test IP"},
        )
        heartbeat = self.client.post(
            "/v1/agents/heartbeat",
            json={"siteId": site_id, "agentToken": enrolled["agentToken"]},
        ).json()
        events = self.client.post(
            "/v1/agents/events",
            json={
                "siteId": site_id,
                "agentToken": enrolled["agentToken"],
                "events": [{"attackType": "dos_http_flood", "severity": "critical", "sourceIp": "8.8.8.8"}],
            },
        ).json()

        self.assertIn("8.8.8.8", heartbeat["allowlist"])
        self.assertFalse(events["responses"][0]["block"])
        self.assertEqual(events["responses"][0]["reason"], "allowlisted")

    def test_blocklist_and_unblock_command_flow(self):
        created = self.client.post("/v1/sites", json={"name": "Demo", "domain": "example.com"}).json()
        site_id = created["site"]["id"]
        dashboard_token = created["dashboardToken"]
        enrolled = self.client.post(
            "/v1/agents/enroll",
            json={"siteId": site_id, "enrollToken": created["enrollmentToken"], "hostname": "test-host"},
        ).json()

        self.client.post(
            "/v1/agents/block-result",
            json={
                "siteId": site_id,
                "agentToken": enrolled["agentToken"],
                "sourceIp": "8.8.8.8",
                "attackType": "dos_http_flood",
                "ruleId": "single_ip_flood",
                "action": "block",
                "status": "success",
                "ports": [80, 443],
            },
        )
        blocks = self.client.get(
            f"/v1/sites/{site_id}/blocks",
            headers={"Authorization": f"Bearer {dashboard_token}"},
        ).json()
        queued = self.client.post(
            f"/v1/sites/{site_id}/blocks/8.8.8.8/unblock",
            headers={"Authorization": f"Bearer {dashboard_token}"},
        ).json()
        heartbeat = self.client.post(
            "/v1/agents/heartbeat",
            json={"siteId": site_id, "agentToken": enrolled["agentToken"]},
        ).json()

        self.assertEqual(blocks["items"][0]["source_ip"], "8.8.8.8")
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(heartbeat["commands"][0]["type"], "unblock")


if __name__ == "__main__":
    unittest.main()
