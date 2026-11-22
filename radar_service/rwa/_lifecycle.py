"""Lightweight standalone background thread lifecycle helper."""
import threading
STOP_EVENT = threading.Event()
def is_stopping() -> bool:
    return STOP_EVENT.is_set()
def request_stop() -> None:
    STOP_EVENT.set()
