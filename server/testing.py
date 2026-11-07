"""Helpers shared by tests/ and evaluation/."""
from fastapi.testclient import TestClient

from .app import create_app
from .config import Settings


class FakeClock:
    def __init__(self, start: int = 1_800_000_000):
        self.now = start

    def __call__(self) -> int:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


def make_clients(settings: Settings, clock: FakeClock):
    """Return (app, browser, phone). Separate clients = separate cookie jars."""
    app = create_app(settings, clock=clock)
    return app, TestClient(app, base_url="https://testserver"), TestClient(app, base_url="https://testserver")
