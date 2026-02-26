import logging
import os
import threading


class RequestQueue:
    """Semaphore-based concurrency limiter for Chrome browser operations.

    Prevents CPU thrashing on low-powered devices by limiting concurrent
    Chrome instances. Requests wait in line rather than being rejected.
    """

    def __init__(self, max_concurrent: int = None, queue_timeout: int = None):
        self.max_concurrent = max_concurrent or int(os.environ.get('MAX_CONCURRENT_BROWSERS', '1'))
        self.queue_timeout = queue_timeout or int(os.environ.get('REQUEST_QUEUE_TIMEOUT', '600'))
        self._semaphore = threading.Semaphore(self.max_concurrent)
        self._waiting = 0
        self._lock = threading.Lock()

    def acquire(self, timeout: int = None):
        timeout = timeout if timeout is not None else self.queue_timeout
        with self._lock:
            self._waiting += 1
            waiting = self._waiting
        if waiting > 1:
            logging.info(f"Request queue: waiting for browser slot ({waiting} in queue)")
        acquired = self._semaphore.acquire(timeout=timeout)
        with self._lock:
            self._waiting -= 1
        if not acquired:
            raise Exception(f"Request queue: timed out after {timeout}s waiting for browser slot")
        logging.debug("Request queue: browser slot acquired")

    def release(self):
        self._semaphore.release()
        logging.debug("Request queue: browser slot released")
