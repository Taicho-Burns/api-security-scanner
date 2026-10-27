"""Shared fixtures: run the two test APIs in background threads for the suite."""
import threading
import time

import pytest
from werkzeug.serving import make_server

from testapi.vulnerable_api import app as vuln_app
from testapi.secure_api import app as secure_app


class _Server(threading.Thread):
    def __init__(self, app, port):
        super().__init__(daemon=True)
        self.srv = make_server("127.0.0.1", port, app, threaded=True)

    def run(self):
        self.srv.serve_forever()

    def stop(self):
        self.srv.shutdown()


@pytest.fixture(scope="session")
def vuln_url():
    s = _Server(vuln_app, 9100)
    s.start(); time.sleep(0.4)
    yield "http://127.0.0.1:9100"
    s.stop()


@pytest.fixture(scope="session")
def secure_url():
    s = _Server(secure_app, 9101)
    s.start(); time.sleep(0.4)
    yield "http://127.0.0.1:9101"
    s.stop()
