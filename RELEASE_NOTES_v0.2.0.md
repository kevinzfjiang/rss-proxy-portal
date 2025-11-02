# RSS Proxy Portal v0.2.0

Release date: 2025-11-02

Highlights:

- UI overhaul: modern dark theme, card layout, improved forms, copy-to-clipboard for feed links
- Fix: feed URL overflow in Current Feeds
- Settings page (admin): configure fetch interval, persisted to SQLite
- Configurable fetch interval via env `FETCH_INTERVAL_SECONDS`, CLI `[port] [fetch_interval_seconds]`, and UI
- Background fetcher reads latest interval from DB each cycle
- Encoding fixes: preserve source bytes, prefer XML prolog encoding, set charset in response (fixes Chinese garbled text)

Notes:
- Default admin user: `admin/admin` (change immediately)
- SECRET_KEY should be set in production
