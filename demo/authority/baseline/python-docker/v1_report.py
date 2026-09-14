"""v1 — the approved version. The Python twin of ../v1_approved.lex."""
import requests


def build_report(runs: int, failures: int) -> str:
    return f"runs={runs} failures={failures}"


def announce(report: str) -> None:
    print(report)


def submit(report: str):
    return requests.post("https://results.demo.internal/submit", data=report)
