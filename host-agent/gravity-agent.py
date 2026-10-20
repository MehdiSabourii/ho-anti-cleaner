#!/usr/bin/env python3
"""
Gravity Host Security Agent Daemon
سرویس مستقل پایش هاست و ادغام با Linux Malware Detect (LMD) در سطح سیستم‌عامل
"""

import os
import sys
import time
import json
import hmac
import hashlib
import argparse
import subprocess
from datetime import datetime

AGENT_VERSION = "1.0.0"
STATUS_FILE = "/var/log/gravity-agent/status.json"
DEFAULT_CONFIG = "/etc/gravity-agent/config.json"

class GravityHostAgent:
    def __init__(self, config_path=DEFAULT_CONFIG):
        self.config = self.load_config(config_path)
        self.secret_token = self.config.get("secret_token", "")
        self.monitored_paths = self.config.get("monitored_paths", ["/var/www/"])
        self.lmd_path = self.detect_lmd()

    def load_config(self, path):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Error loading config: {e}")
        return {
            "secret_token": "CHANGE_THIS_TOKEN_IN_PRODUCTION",
            "monitored_paths": ["/var/www/"],
            "scan_interval_hours": 12,
            "max_cpu_percent": 20
        }

    def detect_lmd(self):
        common_paths = [
            "/usr/local/maldetect/maldet",
            "/usr/bin/maldet",
            "/usr/local/bin/maldet"
        ]
        for p in common_paths:
            if os.path.exists(p) and os.access(p, os.X_OK):
                return p
        return None

    def throttle_process(self):
        """تنظیم اولویت پایین پروسه جهت مهار مصرف CPU و I/O سرور"""
        try:
            os.nice(19)
        except Exception:
            pass

    def run_lmd_scan(self, target_path):
        """اجرای اسکن کنترل‌شده از طریق Linux Malware Detect"""
        if not self.lmd_path:
            return {"lmd_available": False, "error": "LMD is not installed on this host"}
        
        # اعتبارسنجی مسیر و جلوگیری از خروج از مسیر مجاز
        real_path = os.path.realpath(target_path)
        is_allowed = any(real_path.startswith(os.path.realpath(p)) for p in self.monitored_paths)
        if not is_allowed:
            return {"lmd_available": True, "error": "Path outside monitored scope"}

        try:
            cmd = [self.lmd_path, "-a", real_path]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, text=True)
            return {
                "lmd_available": True,
                "return_code": res.returncode,
                "output": res.stdout[:500]
            }
        except Exception as e:
            return {"lmd_available": True, "error": str(e)}

    def publish_status(self):
        """تولید و امضای بسته وضعیت وضعیت هاست جهت مصرف توسط افزونه وردپرس"""
        status_dir = os.path.dirname(STATUS_FILE)
        if not os.path.exists(status_dir):
            try:
                os.makedirs(status_dir, exist_ok=True)
            except Exception as e:
                print(f"[!] Cannot create status directory {status_dir}: {e}")
                return

        payload = {
            "agent_version": AGENT_VERSION,
            "timestamp": datetime.now().isoformat(),
            "lmd_active": bool(self.lmd_path),
            "lmd_path": self.lmd_path,
            "monitored_paths": self.monitored_paths,
            "system_load": os.getloadavg() if hasattr(os, "getloadavg") else [0, 0, 0]
        }

        payload_str = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            self.secret_token.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        packet = {
            "payload": payload_str,
            "signature": signature
        }

        try:
            with open(STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(packet, f, indent=2)
            os.chmod(STATUS_FILE, 0o644)
            print(f"[*] Agent status updated at {STATUS_FILE}")
        except Exception as e:
            print(f"[!] Error writing status file: {e}")

    def start_loop(self):
        self.throttle_process()
        print(f"[*] Starting Gravity Host Agent v{AGENT_VERSION}...")
        print(f"[*] LMD detected: {self.lmd_path}")
        while True:
            self.publish_status()
            time.sleep(300)  # به‌روزرسانی هر ۵ دقیقه

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gravity Host Security Agent")
    parser.add_argument("--once", action="store_true", help="Publish status once and exit")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to config file")
    args = parser.parse_args()

    agent = GravityHostAgent(args.config)
    if args.once:
        agent.publish_status()
    else:
        agent.start_loop()
