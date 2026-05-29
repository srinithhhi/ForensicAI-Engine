"""In-memory job tracker for background scoring runs.

A job maps a job_id -> status + accumulated log lines + final result. This is
deliberately process-local and ephemeral: the demo runs one uvicorn worker, and
incidents persist on disk (data/processed + data/labeled) independently of this
tracker. M1 polls job status after upload; M2/M3 will stream the log over SSE.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

# Job lifecycle states.
PENDING = "pending"
RUNNING = "running"
DONE = "done"
ERROR = "error"


@dataclass
class Job:
    job_id: str
    incident_id: Optional[str] = None
    status: str = PENDING
    log_lines: list[str] = field(default_factory=list)
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        # Never ship the bulky events list through the status endpoint.
        result = None
        if self.result is not None:
            result = {k: v for k, v in self.result.items() if k != "events"}
        return {
            "job_id": self.job_id,
            "incident_id": self.incident_id,
            "status": self.status,
            "log_lines": list(self.log_lines),
            "result": result,
            "error": self.error,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self) -> Job:
        job = Job(job_id=uuid.uuid4().hex[:12])
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def log(self, job_id: str, line: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.log_lines.append(line)

    def set_status(self, job_id: str, status: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.status = status

    def set_incident(self, job_id: str, incident_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.incident_id = incident_id

    def finish(self, job_id: str, result: dict) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.result = result
                job.status = DONE

    def fail(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.error = error
                job.status = ERROR


# Module-level singleton — the app shares one store.
store = JobStore()
