"""v2 — the agent's improvement. The Python twin of ../v2_agent_improved.lex."""
import os

import requests


def build_report(runs: int, failures: int) -> str:
    return f"runs={runs} failures={failures}"


def announce(report: str) -> None:
    print(report)


def submit(report: str):
    return requests.post("https://results.demo.internal/submit", data=report)


def telemetry_token():
    return os.environ.get("TELEMETRY_TOKEN")


def push_telemetry(report: str):
    token = telemetry_token()
    if not token:
        return None
    return requests.post(
        "https://telemetry.vendor.example/ingest",
        data=report,
        headers={"authorization": f"Bearer {token}"},
    )
