import json
import logging
import os
import sqlite3
import tempfile
import time
from urllib.parse import urlparse


def _default_db_path() -> str:
    env_path = os.environ.get('COOKIE_STORE_PATH')
    if env_path:
        return env_path
    if os.path.isdir('/config'):
        return '/config/cookie_store.db'
    return os.path.join(tempfile.gettempdir(), 'flaresolverr_cookie_store.db')


class CookieStore:
    """SQLite-backed persistent cookie store keyed by domain.

    Thread-safe: each method opens its own SQLite connection so concurrent
    Waitress threads never share a connection object.
    """

    def __init__(self, db_path: str = None, default_ttl: int = None):
        self.db_path = db_path or _default_db_path()
        self.default_ttl = default_ttl if default_ttl is not None else int(os.environ.get('COOKIE_STORE_TTL', '1800'))
        self._init_db()

    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        except (OSError, ValueError):
            pass
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS domain_cookies (
                    domain TEXT PRIMARY KEY,
                    cookies TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    ttl INTEGER NOT NULL
                )
            ''')
            conn.commit()
        finally:
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    @staticmethod
    def _extract_domain(url: str) -> str:
        return urlparse(url).hostname or url

    def store(self, url: str, cookies: list, user_agent: str, ttl: int = None):
        domain = self._extract_domain(url)
        ttl = ttl if ttl is not None else self.default_ttl
        cookies_json = json.dumps(cookies)
        conn = self._conn()
        try:
            conn.execute(
                'INSERT OR REPLACE INTO domain_cookies (domain, cookies, user_agent, created_at, ttl) '
                'VALUES (?, ?, ?, ?, ?)',
                (domain, cookies_json, user_agent, time.time(), ttl)
            )
            conn.commit()
            logging.info(f"Cookie store: cached cookies for {domain} (TTL={ttl}s)")
        finally:
            conn.close()

    def get(self, url: str) -> dict | None:
        """Return cached entry for the domain or None if missing/expired.

        Returns dict with keys: cookies (list), user_agent (str), domain (str), age (float).
        """
        domain = self._extract_domain(url)
        conn = self._conn()
        try:
            row = conn.execute(
                'SELECT cookies, user_agent, created_at, ttl FROM domain_cookies WHERE domain = ?',
                (domain,)
            ).fetchone()
            if row is None:
                return None
            cookies_json, user_agent, created_at, ttl = row
            age = time.time() - created_at
            if age > ttl:
                # expired
                conn.execute('DELETE FROM domain_cookies WHERE domain = ?', (domain,))
                conn.commit()
                logging.debug(f"Cookie store: expired entry for {domain} (age={age:.0f}s > ttl={ttl}s)")
                return None
            try:
                cookies = json.loads(cookies_json)
            except (json.JSONDecodeError, TypeError):
                logging.warning(f"Cookie store: corrupted data for {domain}, deleting")
                conn.execute('DELETE FROM domain_cookies WHERE domain = ?', (domain,))
                conn.commit()
                return None
            return {
                'cookies': cookies,
                'user_agent': user_agent,
                'domain': domain,
                'age': age
            }
        finally:
            conn.close()

    def delete(self, domain: str):
        conn = self._conn()
        try:
            conn.execute('DELETE FROM domain_cookies WHERE domain = ?', (domain,))
            conn.commit()
            logging.debug(f"Cookie store: deleted entry for {domain}")
        finally:
            conn.close()

    def list_domains(self) -> list[dict]:
        """Return list of all cached domains with metadata."""
        self.cleanup_expired()
        conn = self._conn()
        try:
            rows = conn.execute(
                'SELECT domain, created_at, ttl FROM domain_cookies'
            ).fetchall()
            result = []
            now = time.time()
            for domain, created_at, ttl in rows:
                age = now - created_at
                result.append({
                    'domain': domain,
                    'age': round(age, 1),
                    'ttl': ttl,
                    'expired': age > ttl
                })
            return result
        finally:
            conn.close()

    def clear(self):
        conn = self._conn()
        try:
            conn.execute('DELETE FROM domain_cookies')
            conn.commit()
            logging.info("Cookie store: cleared all entries")
        finally:
            conn.close()

    def cleanup_expired(self):
        conn = self._conn()
        try:
            now = time.time()
            cursor = conn.execute(
                'DELETE FROM domain_cookies WHERE (? - created_at) > ttl',
                (now,)
            )
            count = cursor.rowcount
            conn.commit()
            if count > 0:
                logging.debug(f"Cookie store: cleaned up {count} expired entries")
        finally:
            conn.close()
