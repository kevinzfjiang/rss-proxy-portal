# Changelog

All notable changes to this project will be documented in this file.

## 2025-11-02

- UI overhaul: modern dark theme, cards, improved forms, copy-to-clipboard for feed links
- Fix: feed URL overflow in Current Feeds
- Feature: Settings page (admin) to configure fetch interval (persisted to SQLite)
- Config: Fetch interval configurable via env `FETCH_INTERVAL_SECONDS`, CLI `[port] [fetch_interval_seconds]`, and UI
- Behavior: Background fetcher reads latest interval from DB each cycle
- Fix: Encoding handling for feeds (preserve source bytes, prefer XML prolog encoding, set charset in response)
