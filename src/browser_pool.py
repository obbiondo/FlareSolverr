import logging
import os
import queue
import threading
import time

from func_timeout import func_timeout, FunctionTimedOut

import utils


class BrowserPool:
    """Pool of pre-warmed Chrome/WebDriver instances.

    Eliminates Chrome startup latency (2-5s) by keeping warm instances ready.
    Instances are recycled after a configurable number of requests to prevent
    Chrome memory bloat.
    """

    def __init__(self, pool_size: int = None, max_requests: int = None):
        self.pool_size = pool_size if pool_size is not None else int(os.environ.get('BROWSER_POOL_SIZE', '1'))
        self.max_requests = max_requests if max_requests is not None else int(
            os.environ.get('BROWSER_POOL_MAX_REQUESTS', '50'))
        self._pool = queue.Queue(maxsize=self.pool_size)
        self._request_counts = {}  # driver id -> request count
        self._lock = threading.Lock()
        self._health_thread = None
        self._stopped = False
        self._refilling = False

    def start(self):
        if self.pool_size <= 0:
            logging.info("Browser pool: disabled (pool_size=0)")
            return
        logging.info(f"Browser pool: warming {self.pool_size} instance(s)...")
        for i in range(self.pool_size):
            try:
                driver = self._create_instance()
                self._pool.put(driver, block=False)
                logging.info(f"Browser pool: instance {i + 1}/{self.pool_size} ready")
            except Exception as e:
                logging.error(f"Browser pool: failed to create instance {i + 1}: {e}")

        if self.pool_size > 1:
            self._health_thread = threading.Thread(target=self._health_check_loop, daemon=True)
            self._health_thread.start()
            logging.info(f"Browser pool: started (size={self.pool_size}, max_requests={self.max_requests})")
        else:
            logging.info(f"Browser pool: started (size={self.pool_size}, max_requests={self.max_requests}, health check skipped)")

    def _create_instance(self):
        driver = utils.get_webdriver()
        with self._lock:
            self._request_counts[id(driver)] = 0
        return driver

    def checkout(self, timeout: float = 30) -> tuple:
        """Get an instance from the pool.

        Returns (driver, pool_managed) tuple. pool_managed is True if the
        driver came from the pool and should be returned via checkin().
        Timeout is 30s to accommodate Chrome startup (60-180s on low-powered
        devices) and queue wait when instances are being recycled.
        """
        if self.pool_size <= 0:
            return utils.get_webdriver(), False

        try:
            driver = self._pool.get(timeout=timeout)
        except queue.Empty:
            logging.warning("Browser pool: exhausted, creating temporary instance")
            return utils.get_webdriver(), False

        # Health check + cookie cleanup (about:blank navigation removed —
        # _evil_logic() navigates to the target URL immediately anyway)
        try:
            driver.delete_all_cookies()
        except Exception:
            logging.warning("Browser pool: instance unhealthy on checkout, creating replacement")
            self._safe_quit(driver)
            try:
                driver = self._create_instance()
            except Exception:
                logging.error("Browser pool: replacement failed, using temporary instance")
                return utils.get_webdriver(), False

        with self._lock:
            self._request_counts[id(driver)] = self._request_counts.get(id(driver), 0) + 1
            count = self._request_counts[id(driver)]

        logging.debug(f"Browser pool: checked out instance (request #{count})")
        return driver, True

    def checkin(self, driver):
        """Return an instance to the pool after use."""
        if driver is None:
            return

        with self._lock:
            count = self._request_counts.get(id(driver), 0)

        # recycle if max requests reached — async to avoid blocking the response
        # (Chrome startup can take 60-180s on low-powered devices like QNAP)
        if count >= self.max_requests:
            logging.info(f"Browser pool: recycling instance after {count} requests")
            self._safe_quit(driver)
            with self._lock:
                if self._refilling:
                    logging.debug("Browser pool: refill already in progress, skipping")
                    return
                self._refilling = True
            threading.Thread(target=self._refill_pool, daemon=True,
                             name="pool-refill").start()
            return

        try:
            self._pool.put(driver, block=False)
            logging.debug("Browser pool: instance returned to pool")
        except queue.Full:
            logging.warning("Browser pool: pool full, quitting instance")
            self._safe_quit(driver)

    def _refill_pool(self):
        """Create a replacement instance in the background after recycling."""
        try:
            driver = self._create_instance()
            try:
                self._pool.put(driver, block=False)
                logging.info("Browser pool: replacement instance ready")
            except queue.Full:
                logging.debug("Browser pool: pool already full, discarding replacement")
                self._safe_quit(driver)
        except Exception as e:
            logging.error(f"Browser pool: async replacement failed: {e}")
        finally:
            with self._lock:
                self._refilling = False

    def _safe_quit(self, driver):
        with self._lock:
            self._request_counts.pop(id(driver), None)
        try:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
        except Exception:
            pass

    def _health_check_loop(self):
        while not self._stopped:
            time.sleep(60)
            if self._stopped:
                break
            self._health_check()

    def _health_check(self):
        """Verify pool instances are responsive, replace dead ones.

        Processes one instance at a time (get → check → put back) to avoid
        draining the entire pool and leaving it empty during the check.
        """
        count = self._pool.qsize()
        for _ in range(count):
            try:
                driver = self._pool.get_nowait()
            except queue.Empty:
                break
            try:
                func_timeout(10, lambda: driver.title)
                self._pool.put(driver, block=False)
            except (Exception, FunctionTimedOut):
                logging.warning("Browser pool: replacing unresponsive instance")
                self._safe_quit(driver)
                for attempt in range(2):
                    try:
                        new_driver = self._create_instance()
                        self._pool.put(new_driver, block=False)
                        break
                    except Exception as e:
                        if attempt == 0:
                            time.sleep(1)
                        else:
                            logging.error(f"Browser pool: pool capacity reduced — failed to create replacement: {e}")

    def shutdown(self):
        self._stopped = True
        while True:
            try:
                driver = self._pool.get_nowait()
                self._safe_quit(driver)
            except queue.Empty:
                break
        logging.info("Browser pool: shut down")
