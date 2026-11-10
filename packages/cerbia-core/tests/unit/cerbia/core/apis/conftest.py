from collections.abc import Callable

import httpx2
import pytest


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable[[httpx2.Request], httpx2.Response]], None]:
    def install(handler: Callable[[httpx2.Request], httpx2.Response]) -> None:
        monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", lambda self, request: handler(request))

    return install
