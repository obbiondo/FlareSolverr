# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FlareSolverr is a Python proxy server that bypasses Cloudflare and similar anti-bot protections using headless Chrome automation via Selenium and undetected-chromedriver. It exposes an HTTP API on port 8191.

## Commands

### Run locally
```bash
pip install -r requirements.txt
python src/flaresolverr.py
```

### Run with Docker
```bash
docker-compose up -d
```

### Run tests
```bash
pip install -r test-requirements.txt
cd src && python -m unittest tests.py -v
```

### Run a single test
```bash
cd src && python -m unittest tests.TestFlareSolverr.test_index_endpoint
```

### Run real-world site tests (requires network + Chrome)
```bash
cd src && python -m unittest tests_sites.py
```

### Build standalone binary
```bash
python src/build_package.py
```

There is no configured linter.

## Architecture

### Request Flow
```
POST /v1 → controller_v1() → _controller_v1_handler()
  → Command dispatcher (_cmd_request_get, _cmd_request_post, _cmd_sessions_*)
  → _resolve_challenge() → _evil_logic() (Selenium automation)
  → V1ResponseBase returned as JSON
```

### Key Source Files (all under `src/`)

- **flaresolverr.py** — Entry point. Bottle web app setup, plugin registration, Waitress server startup, environment config loading.
- **flaresolverr_service.py** — Core business logic. Challenge detection (by page title and CSS selectors), challenge solving loop, Turnstile CAPTCHA handling, cookie/header extraction, screenshot capture.
- **utils.py** — Browser utilities. Chrome/Chromium detection and version extraction, WebDriver initialization via undetected-chromedriver, proxy extension generation, Xvfb virtual display management, platform detection.
- **dtos.py** — Data transfer objects. `V1RequestBase` (incoming params), `V1ResponseBase` (API response), `ChallengeResolutionT` (solution details).
- **sessions.py** — `SessionsStorage` class managing a pool of persistent WebDriver instances with TTL support.
- **metrics.py** — Prometheus metrics integration.

### Bottle Plugins (`src/bottle_plugins/`)
- **error_plugin** — Exception handling for all routes
- **logger_plugin** — HTTP request/response logging
- **prometheus_plugin** — Metrics collection

### Bundled Dependencies
- `src/undetected_chromedriver/` — Bundled fork of undetected-chromedriver (not installed via pip)

### API
Single endpoint `POST /v1` dispatches on the `cmd` field:
- `request.get` / `request.post` — Fetch URL, solve challenges, return HTML/cookies
- `sessions.create` / `sessions.list` / `sessions.destroy` — Manage persistent browser sessions

### Challenge Detection Strategy
Detection checks page title ("Just a moment...", "DDoS-Guard") and CSS selectors (`#cf-challenge-running`, `.ray_id`, `#turnstile-wrapper`, etc.). Solving polls until challenge selectors disappear, clicks verify buttons if found, and handles page reloads.

### Environment Variables
Key config (all optional): `LOG_LEVEL`, `LOG_HTML`, `HEADLESS` (default true), `DISABLE_MEDIA`, `PORT` (default 8191), `HOST`, `PROXY_URL`/`PROXY_USERNAME`/`PROXY_PASSWORD`, `CAPTCHA_SOLVER`, `TZ`, `LANG`, `PROMETHEUS_ENABLED`, `PROMETHEUS_PORT`, `TEST_URL`.

### Testing
Tests use Python `unittest` with **WebTest** (WSGI-level testing without a running server). `tests.py` covers API validation, endpoints, sessions, and proxies. `tests_sites.py` tests against real Cloudflare-protected sites.
