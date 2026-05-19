import argparse
import json
import os
import re
import socket
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import ipaddress

import requests


VERSION = "0.1.0"
DEFAULT_LOG_PATHS = [
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
]
SUSPICIOUS_PATHS = (
    "/.env",
    "/phpmyadmin",
    "/.git",
    "/backup",
    "/config",
    "/server-status",
)
LOGIN_PATHS = (
    "/wp-login.php",
    "/xmlrpc.php",
    "/login",
    "/admin",
    "/user/login",
    "/account/login",
)
PAYLOAD_PATTERNS = (
    "../",
    "%2e%2e",
    "union%20select",
    "union select",
    "' or ",
    "\" or ",
    "<script",
    "cmd=",
)
STATUS_SPIKE_CODES = {401, 403, 404, 429, 500}
WEB_BLOCK_PORTS = [80, 443]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(tmp_path, path)


def parse_nginx_access(line):
    pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
        r"(?P<status>\d{3}) \S+ "
        r'"[^"]*" "(?P<ua>[^"]*)"'
    )
    match = pattern.search(line)
    if not match:
        return None
    return {
        "sourceIp": match.group("ip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "statusCode": int(match.group("status")),
        "userAgent": match.group("ua"),
        "raw": line.strip(),
    }


def parse_apache_access(line):
    return parse_nginx_access(line)


def parse_error_log(line):
    ip_match = re.search(r"client: (?P<ip>[0-9a-fA-F:.]+)", line)
    path_match = re.search(r'(?:"GET|POST|HEAD|PUT|DELETE) (?P<path>\S+)', line)
    if not ip_match:
        return None
    return {
        "sourceIp": ip_match.group("ip"),
        "method": None,
        "path": path_match.group("path") if path_match else "server_error",
        "statusCode": 500,
        "userAgent": "",
        "raw": line.strip(),
    }


def parse_log_line(path, line):
    if "access" in path:
        return parse_nginx_access(line) or parse_apache_access(line)
    return parse_error_log(line)


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


class Detector:
    def __init__(self):
        self.ip_hits = defaultdict(lambda: deque(maxlen=300))
        self.status_hits = defaultdict(lambda: deque(maxlen=100))
        self.login_hits = defaultdict(lambda: deque(maxlen=100))
        self.path_hits = defaultdict(lambda: deque(maxlen=700))
        self.site_hits = deque(maxlen=1200)

    def inspect(self, record):
        if not record:
            return None
        source_ip = record["sourceIp"]
        path = (record.get("path") or "").lower()
        status = int(record.get("statusCode") or 0)
        ts = datetime.now(timezone.utc)

        self.ip_hits[source_ip].append((ts, record))
        self.path_hits[path].append((ts, record))
        self.site_hits.append((ts, record))
        if status in STATUS_SPIKE_CODES:
            self.status_hits[(source_ip, status)].append((ts, record))
        if self._is_login_path(path):
            self.login_hits[source_ip].append((ts, record))

        login_count = self._recent_count(self.login_hits[source_ip], ts, 300)
        failed_auth_count = self._recent_status_count(source_ip, ts, 300, {401, 403, 429})
        ip_count = self._recent_count(self.ip_hits[source_ip], ts, 60)
        path_count = self._recent_count(self.path_hits[path], ts, 60) if path else 0
        site_count = self._recent_count(self.site_hits, ts, 60)

        if login_count >= 8:
            return self._event("brute_force", "high", "repeated_login_attempts", record, login_count)
        if failed_auth_count >= 10:
            return self._event("brute_force", "high", "repeated_auth_failures", record, failed_auth_count)
        if ip_count >= 300:
            return self._event("dos_http_flood", "critical", "single_ip_flood_critical", record, ip_count)
        if ip_count >= 120:
            return self._event("dos_http_flood", "high", "single_ip_flood", record, ip_count)
        if path and path_count >= 250:
            return self._event("dos_http_flood", "high", "same_path_flood", record, path_count)
        if site_count >= 600:
            return self._event("dos_http_flood", "critical", "site_wide_request_flood", record, site_count)
        if any(marker in path for marker in SUSPICIOUS_PATHS):
            return self._event("sensitive_file_scan", "high", "sensitive_path_scan", record, 1)
        if any(marker in path for marker in PAYLOAD_PATTERNS):
            return self._event("suspicious_payload", "critical", "suspicious_payload", record, 1)
        if status in STATUS_SPIKE_CODES and self._recent_count(self.status_hits[(source_ip, status)], ts, 120) >= 15:
            return self._event("web_scan", "high", f"status_{status}_spike", record, self._recent_count(self.status_hits[(source_ip, status)], ts, 120))
        return None

    @staticmethod
    def _is_login_path(path):
        return any(marker in path for marker in LOGIN_PATHS)

    @staticmethod
    def _recent_count(items, ts, seconds):
        cutoff = ts - timedelta(seconds=seconds)
        return sum(1 for item_ts, _ in items if item_ts >= cutoff)

    def _recent_status_count(self, source_ip, ts, seconds, statuses):
        cutoff = ts - timedelta(seconds=seconds)
        count = 0
        for status in statuses:
            count += sum(1 for item_ts, _ in self.status_hits[(source_ip, status)] if item_ts >= cutoff)
        return count

    @staticmethod
    def _event(attack_type, severity, rule_id, record, count):
        return {
            "id": f"evt_{uuid4().hex[:12]}",
            "timestamp": now_iso(),
            "attackType": attack_type,
            "severity": severity,
            "sourceIp": record.get("sourceIp", "Unknown"),
            "method": record.get("method"),
            "path": record.get("path"),
            "statusCode": record.get("statusCode"),
            "userAgent": record.get("userAgent", ""),
            "ruleId": rule_id,
            "eventCount": count,
            "sampleLines": [record.get("raw", "")][:5],
        }


class LogTailer:
    def __init__(self, paths):
        self.paths = [path for path in paths if Path(path).exists()]
        self.positions = {}

    def poll(self):
        records = []
        for path in self.paths:
            current = Path(path)
            try:
                size = current.stat().st_size
                last_position = self.positions.get(path, size)
                if size < last_position:
                    last_position = 0
                with open(current, "r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(last_position)
                    for line in handle:
                        record = parse_log_line(path, line)
                        if record:
                            records.append(record)
                    self.positions[path] = handle.tell()
            except PermissionError:
                print(f"Permission denied reading {path}. Run the agent with sudo.")
            except FileNotFoundError:
                continue
        return records


class AstraAgent:
    def __init__(self, config):
        self.config = config
        self.backend_url = config["backend_url"].rstrip("/")
        self.site_id = config["site_id"]
        self.interval = int(config.get("interval") or 10)
        self.state_dir = Path(config.get("state_dir") or ".astra-agent")
        self.queue_path = self.state_dir / "queue.json"
        self.blocks_path = self.state_dir / "blocks.json"
        self.detector = Detector()
        self.tailer = LogTailer(config.get("log_paths") or DEFAULT_LOG_PATHS)
        self.queue = load_json(self.queue_path, [])
        self.blocks = load_json(self.blocks_path, {})
        self.allowlist = set(config.get("allowlist") or [])

    @property
    def agent_token(self):
        return self.config.get("agent_token") or ""

    def save_config(self):
        if self.config.get("_config_path"):
            write_json(self.config["_config_path"], {k: v for k, v in self.config.items() if k != "_config_path"})

    def enroll(self):
        if self.agent_token:
            return
        payload = {
            "siteId": self.site_id,
            "enrollToken": self.config.get("enroll_token"),
            "hostname": socket.gethostname(),
            "version": VERSION,
        }
        response = requests.post(f"{self.backend_url}/v1/agents/enroll", json=payload, timeout=15)
        response.raise_for_status()
        body = response.json()
        self.config["agent_token"] = body["agentToken"]
        self.save_config()
        print("ASTRA enrollment completed.")

    def heartbeat(self):
        payload = {"siteId": self.site_id, "agentToken": self.agent_token}
        response = requests.post(f"{self.backend_url}/v1/agents/heartbeat", json=payload, timeout=15)
        response.raise_for_status()
        body = response.json()
        self.allowlist = set(body.get("allowlist") or [])
        return body

    def enqueue(self, event):
        self.queue.append(event)
        write_json(self.queue_path, self.queue)

    def flush_queue(self):
        if not self.queue:
            return
        payload = {"siteId": self.site_id, "agentToken": self.agent_token, "events": self.queue}
        response = requests.post(f"{self.backend_url}/v1/agents/events", json=payload, timeout=20)
        response.raise_for_status()
        body = response.json()
        for item in body.get("responses", []):
            if item.get("block"):
                matching = next((event for event in self.queue if event["id"] == item["eventId"]), None)
                if matching:
                    self.apply_block(matching, item)
        self.queue = []
        write_json(self.queue_path, self.queue)

    def apply_block(self, event, decision):
        source_ip = event.get("sourceIp")
        if not source_ip or not is_public_ip(source_ip):
            self.report_block(event, "skipped", "Refused to block non-public or invalid IP.", None)
            return
        if source_ip in self.allowlist:
            self.report_block(event, "skipped", "Refused to block allowlisted IP.", None)
            return
        existing = self.blocks.get(source_ip)
        if existing and (not parse_time(existing.get("expiresAt")) or parse_time(existing.get("expiresAt")) > datetime.now(timezone.utc)):
            self.report_block(event, "skipped", "IP is already blocked.", existing.get("expiresAt"))
            return
        expires_at = datetime.now(timezone.utc) + timedelta(hours=int(decision.get("blockDurationHours") or 24))
        ports = decision.get("ports") or WEB_BLOCK_PORTS
        results = []
        try:
            for port in ports:
                command = ["ufw", "deny", "from", source_ip, "to", "any", "port", str(port)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                results.append(result)
            failed = [result for result in results if result.returncode != 0]
            if not failed:
                self.blocks[source_ip] = {
                    "eventId": event["id"],
                    "expiresAt": expires_at.isoformat(),
                    "ports": ports,
                    "attackType": event.get("attackType"),
                    "ruleId": event.get("ruleId"),
                }
                write_json(self.blocks_path, self.blocks)
                self.report_block(event, "success", "Blocked web access with UFW on ports 80/443.", expires_at.isoformat(), ports=ports)
            else:
                message = "; ".join(result.stderr.strip() or result.stdout.strip() or "UFW command failed." for result in failed)
                self.report_block(event, "failed", message, expires_at.isoformat(), ports=ports)
        except Exception as exc:
            self.report_block(event, "failed", str(exc), expires_at.isoformat(), ports=ports)

    def expire_blocks(self):
        changed = False
        now = datetime.now(timezone.utc)
        for source_ip, info in list(self.blocks.items()):
            expires_at = parse_time(info.get("expiresAt"))
            if not expires_at or expires_at > now:
                continue
            event = {
                "id": info.get("eventId"),
                "sourceIp": source_ip,
                "attackType": info.get("attackType"),
                "ruleId": info.get("ruleId"),
            }
            status, message = self.unblock_ip(source_ip, info.get("ports") or WEB_BLOCK_PORTS)
            self.report_block(event, status, message, None, action="unblock", ports=info.get("ports") or WEB_BLOCK_PORTS)
            if status == "success":
                del self.blocks[source_ip]
                changed = True
        if changed:
            write_json(self.blocks_path, self.blocks)

    def unblock_ip(self, source_ip, ports=None):
        ports = ports or WEB_BLOCK_PORTS
        try:
            results = []
            for port in ports:
                command = ["ufw", "delete", "deny", "from", source_ip, "to", "any", "port", str(port)]
                results.append(subprocess.run(command, capture_output=True, text=True, timeout=30, check=False))
            failed = [result for result in results if result.returncode != 0]
            if failed:
                message = "; ".join(result.stderr.strip() or result.stdout.strip() or "UFW unblock command failed." for result in failed)
                return "failed", message
            return "success", "Removed UFW web-port block."
        except Exception as exc:
            return "failed", str(exc)

    def process_commands(self, commands):
        changed = False
        for command in commands:
            if command.get("type") != "unblock":
                self.report_command(command, "skipped", "Unsupported command type.")
                continue
            source_ip = command.get("sourceIp")
            local_block = self.blocks.get(source_ip, {})
            status, message = self.unblock_ip(source_ip, local_block.get("ports") or WEB_BLOCK_PORTS)
            event = {
                "id": local_block.get("eventId"),
                "sourceIp": source_ip,
                "attackType": local_block.get("attackType"),
                "ruleId": local_block.get("ruleId"),
            }
            self.report_block(event, status, message, None, action="unblock", ports=local_block.get("ports") or WEB_BLOCK_PORTS)
            self.report_command(command, status, message)
            if status == "success" and source_ip in self.blocks:
                del self.blocks[source_ip]
                changed = True
        if changed:
            write_json(self.blocks_path, self.blocks)

    def report_command(self, command, status, message):
        payload = {
            "siteId": self.site_id,
            "agentToken": self.agent_token,
            "commandId": command.get("id"),
            "status": status,
            "message": message,
        }
        try:
            requests.post(f"{self.backend_url}/v1/agents/command-result", json=payload, timeout=15).raise_for_status()
        except Exception as exc:
            print(f"Could not report command result: {exc}")

    def report_block(self, event, status, message, expires_at, action="block", ports=None):
        payload = {
            "siteId": self.site_id,
            "agentToken": self.agent_token,
            "eventId": event.get("id"),
            "sourceIp": event.get("sourceIp"),
            "attackType": event.get("attackType"),
            "ruleId": event.get("ruleId"),
            "ports": ports or WEB_BLOCK_PORTS,
            "action": action,
            "status": status,
            "message": message,
            "expiresAt": expires_at,
        }
        try:
            requests.post(f"{self.backend_url}/v1/agents/block-result", json=payload, timeout=15).raise_for_status()
        except Exception as exc:
            print(f"Could not report block result: {exc}")

    def run_once(self):
        heartbeat = self.heartbeat()
        self.process_commands(heartbeat.get("commands") or [])
        for record in self.tailer.poll():
            event = self.detector.inspect(record)
            if event:
                self.enqueue(event)
        self.flush_queue()
        self.expire_blocks()

    def run_forever(self):
        self.enroll()
        print(f"ASTRA agent running for {self.site_id}. Watching: {', '.join(self.tailer.paths) or 'no logs found'}")
        while True:
            try:
                self.run_once()
            except Exception as exc:
                print(f"ASTRA agent loop error: {exc}")
            time.sleep(self.interval)


def build_config(args):
    config = load_json(args.config, {}) if args.config else {}
    if args.config:
        config["_config_path"] = args.config
    for key in ("backend_url", "site_id", "enroll_token", "agent_token", "state_dir"):
        value = getattr(args, key, None)
        if value:
            config[key] = value
    if args.interval:
        config["interval"] = args.interval
    if args.log_path:
        config["log_paths"] = args.log_path
    missing = [key for key in ("backend_url", "site_id") if not config.get(key)]
    if missing:
        raise SystemExit(f"Missing required config: {', '.join(missing)}")
    if not config.get("agent_token") and not config.get("enroll_token"):
        raise SystemExit("Either agent_token or enroll_token is required.")
    return config


def main():
    parser = argparse.ArgumentParser(description="ASTRA Linux website security agent")
    parser.add_argument("--config")
    parser.add_argument("--backend-url")
    parser.add_argument("--site-id")
    parser.add_argument("--enroll-token")
    parser.add_argument("--agent-token")
    parser.add_argument("--interval", type=int)
    parser.add_argument("--state-dir")
    parser.add_argument("--log-path", action="append")
    args = parser.parse_args()

    agent = AstraAgent(build_config(args))
    agent.run_forever()


if __name__ == "__main__":
    main()
