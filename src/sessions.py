import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid1

from selenium.webdriver.chrome.webdriver import WebDriver

import utils


@dataclass
class Session:
    session_id: str
    driver: WebDriver
    created_at: datetime

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at


def _safe_quit_driver(driver):
    """Quit a WebDriver instance, suppressing any errors."""
    try:
        if utils.PLATFORM_VERSION == "nt":
            driver.close()
        driver.quit()
    except Exception:
        pass


class SessionsStorage:
    """Thread-safe session storage with background cleanup and max limit."""

    def __init__(self):
        self.sessions = {}
        self._lock = threading.RLock()
        self.max_sessions = int(os.environ.get('MAX_SESSIONS', '10'))
        self.session_ttl_minutes = int(os.environ.get('SESSION_TTL_MINUTES', '30'))
        self._cleanup_thread = None
        self._stopped = False

    def start_cleanup_thread(self):
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logging.info(f"Session cleanup thread started (ttl={self.session_ttl_minutes}m, max={self.max_sessions})")

    def _cleanup_loop(self):
        while not self._stopped:
            time.sleep(60)
            if self._stopped:
                break
            self._cleanup_expired()

    def _cleanup_expired(self):
        ttl = timedelta(minutes=self.session_ttl_minutes)
        to_destroy = []
        with self._lock:
            for session_id, session in list(self.sessions.items()):
                if session.lifetime() > ttl:
                    to_destroy.append(session_id)
        for session_id in to_destroy:
            logging.info(f"Session cleanup: destroying expired session {session_id}")
            self.destroy(session_id)

    def create(self, session_id: Optional[str] = None, proxy: Optional[dict] = None,
               force_new: Optional[bool] = False) -> Tuple[Session, bool]:
        """create creates new instance of WebDriver if necessary,
        assign defined (or newly generated) session_id to the instance
        and returns the session object. If a new session has been created
        second argument is set to True.

        Note: The function is idempotent, so in case if session_id
        already exists in the storage a new instance of WebDriver won't be created
        and existing session will be returned. Second argument defines if
        new session has been created (True) or an existing one was used (False).
        """
        session_id = session_id or str(uuid1())

        old_session = None
        with self._lock:
            if force_new:
                old_session = self._destroy_unlocked(session_id)

            if session_id in self.sessions:
                return self.sessions[session_id], False

            if len(self.sessions) >= self.max_sessions:
                raise Exception(f"Maximum number of sessions ({self.max_sessions}) reached. "
                                f"Destroy existing sessions first.")

        # Quit old driver OUTSIDE the lock to avoid blocking other session ops
        if old_session:
            _safe_quit_driver(old_session.driver)

        driver = utils.get_webdriver(proxy)
        created_at = datetime.now()
        session = Session(session_id, driver, created_at)

        result = None
        error_msg = None
        driver_to_quit = None
        with self._lock:
            # Re-validate after driver creation — another thread may have
            # created this session or filled the last slot while we were
            # blocked on get_webdriver().
            if session_id in self.sessions:
                driver_to_quit = driver
                result = (self.sessions[session_id], False)
            elif len(self.sessions) >= self.max_sessions:
                driver_to_quit = driver
                error_msg = (f"Maximum number of sessions ({self.max_sessions}) reached. "
                             f"Destroy existing sessions first.")
            else:
                self.sessions[session_id] = session
                result = (session, True)

        # Quit wasted driver OUTSIDE the lock to avoid blocking other session ops
        if driver_to_quit:
            _safe_quit_driver(driver_to_quit)
        if error_msg:
            raise Exception(error_msg)
        return result

    def exists(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self.sessions

    def destroy(self, session_id: str) -> bool:
        """destroy closes the driver instance and removes session from the storage."""
        with self._lock:
            if session_id not in self.sessions:
                return False
            session = self.sessions.pop(session_id)
        # Quit driver OUTSIDE the lock to avoid blocking other session operations
        try:
            if utils.PLATFORM_VERSION == "nt":
                session.driver.close()
            session.driver.quit()
        except Exception as e:
            logging.warning(f"Error destroying session {session_id}: {e}")
        return True

    def _destroy_unlocked(self, session_id: str) -> Optional[Session]:
        """Remove session from dict while lock is held.

        Returns the session so the caller can quit the driver OUTSIDE the lock,
        or None if the session didn't exist.
        """
        if session_id not in self.sessions:
            return None
        return self.sessions.pop(session_id)

    def get(self, session_id: str, ttl: Optional[timedelta] = None) -> Tuple[Session, bool]:
        session, fresh = self.create(session_id)

        if ttl is not None and not fresh and session.lifetime() > ttl:
            logging.debug(f'session\'s lifetime has expired, so the session is recreated (session_id={session_id})')
            session, fresh = self.create(session_id, force_new=True)

        return session, fresh

    def stop(self):
        """Signal the cleanup thread to stop."""
        self._stopped = True

    def session_ids(self) -> list[str]:
        with self._lock:
            return list(self.sessions.keys())
