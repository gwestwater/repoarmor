"""Tests for TruffleHog scanner behavior."""

import json
import queue
import threading
import time
from types import SimpleNamespace

import pytest

from repoarmor.scanner import trufflehog


def test_scan_docker_image_timeout_stops_stdout_worker(monkeypatch):
    """Timed-out Docker scans should not leave the stdout worker blocked."""
    finding_line = json.dumps(
        {
            "DetectorName": "AWS",
            "Raw": "secret-value",
            "Verified": True,
            "SourceMetadata": {"Data": {"Git": {"file": "app.py", "line": 1}}},
        }
    ) + "\n"

    class FakeProcess:
        def __init__(self):
            self.stdout = [finding_line, finding_line, finding_line]
            self.stderr = []
            self.returncode = None
            self.killed = False

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def kill(self):
            self.killed = True

    fake_process = FakeProcess()
    created_threads: list[threading.Thread] = []
    real_thread = threading.Thread
    real_queue = queue.Queue

    class TrackingThread:
        def __init__(self, *args, **kwargs):
            self._thread = real_thread(*args, **kwargs)
            created_threads.append(self._thread)

        def start(self):
            self._thread.start()

        def join(self, timeout=None):
            self._thread.join(timeout=timeout)

        def is_alive(self):
            return self._thread.is_alive()

    class SmallQueue(real_queue):
        def __init__(self, maxsize=0):
            super().__init__(maxsize=1)

    monkeypatch.setattr(trufflehog.subprocess, "Popen", lambda *args, **kwargs: fake_process)
    monkeypatch.setattr(trufflehog.threading, "Thread", TrackingThread)
    monkeypatch.setattr(queue, "Queue", SmallQueue)

    settings = SimpleNamespace(scanner=SimpleNamespace(trufflehog_path="trufflehog", timeout=1))

    scan = trufflehog.scan_docker_image("example:latest", timeout=1, settings=settings)

    first_result = next(scan)
    assert first_result.file_path == "app.py"

    time.sleep(1.1)

    with pytest.raises(trufflehog.TruffleHogError, match="Docker scan timed out after 1 seconds"):
        next(scan)

    assert fake_process.killed is True
    assert created_threads
    assert all(not thread.is_alive() for thread in created_threads)
