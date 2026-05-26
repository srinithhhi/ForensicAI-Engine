"""Meta features: log volume, time-window, class diversity.

These three features describe the bundle as a whole rather than any specific
event class. They're cheap to compute and useful as global priors for the
model (an incident with 5,000 events looks very different from one with
500,000).
"""

from __future__ import annotations


def compute(events: list[dict]) -> dict:
    if not events:
        return {
            "log_lines_total": 0,
            "log_window_hours": 0.0,
            "event_class_diversity": 0,
        }

    classes = {e["class_uid"] for e in events}
    times = [e["time"] for e in events if e["time"] > 0]
    if times:
        span_ms = max(times) - min(times)
        window_hours = round(span_ms / 1000 / 3600, 2)
    else:
        window_hours = 0.0

    return {
        "log_lines_total": len(events),
        "log_window_hours": window_hours,
        "event_class_diversity": len(classes),
    }
