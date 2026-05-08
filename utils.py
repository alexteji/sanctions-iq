"""Shared utilities — HTTP retry, feed fetching."""
import time

import requests


def fetch_with_retry(url, max_attempts=3, backoff=2.0, **kwargs):
    """GET url with exponential-backoff retry. Returns Response; raises on final failure."""
    kwargs.setdefault("timeout", 30)
    last_exc = None
    for attempt in range(max_attempts):
        try:
            resp = requests.get(url, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                wait = backoff * (2 ** attempt)
                print(f"[retry] {url} ({attempt + 1}/{max_attempts}): {exc} — retrying in {wait:.0f}s")
                time.sleep(wait)
    raise last_exc


def fetch_feed(url, timeout=15):
    """Fetch an RSS/Atom feed via requests (with timeout) then parse with feedparser.
    Returns feedparser result or None on error."""
    import feedparser
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "bureauq-sanctions-monitor/1.0 (+https://bureauq.com)"},
        )
        resp.raise_for_status()
        return feedparser.parse(resp.content)
    except Exception as exc:
        print(f"[feed] {url}: {exc}")
        return None
