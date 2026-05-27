"""Pre-discovery target mapping for VibeScan.

The vibe scanner's hit rate depends on the strength of identity tokens fed
into the Serper dork generator. URL-derived identity (`fortra.com` →
`{company_name: "Fortra", domain_root: "fortra"}`) misses apps named after
products rather than the parent organization. Fortra's vibe-coded internal
tool for "Tripwire" wouldn't surface for `site:vercel.app "fortra"`.

This module BFS-crawls 1–2 levels of the target site (title, meta, headings,
body text), then asks GLiNER to label organization/product/brand entities.
The returned token list is fed into `discover()` as additional dork seeds.

Gracefully degrades to an empty list when:
  - GLiNER isn't installed (identity-only dorks still run)
  - The target blocks the crawler / returns no text
  - The crawl exceeds its time budget
"""

import logging
import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from scans import _gliner
from utils.network import is_safe_hostname, is_safe_url


logger = logging.getLogger(__name__)

MAX_PAGES = 50
MAX_DEPTH = 3
REQUEST_TIMEOUT = 8
TIME_BUDGET_S = 20
USER_AGENT = "Mozilla/5.0 (compatible; VibeScan/1.0; +https://github.com/Zendata/vibe-scanner)"

# Common navigation words that GLiNER may flag as "product" but aren't.
STOP_TOKENS = {
    "home",
    "about",
    "contact",
    "products",
    "solutions",
    "services",
    "company",
    "team",
    "careers",
    "blog",
    "news",
    "support",
    "login",
    "sign in",
    "sign up",
    "log in",
    "menu",
    "search",
    "privacy",
    "terms",
    "cookies",
    "english",
    "site",
    "page",
    "click here",
    "learn more",
    "read more",
    "get started",
    "free trial",
}


def _same_host(url: str, host: str) -> bool:
    try:
        h = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return h == host or h.endswith("." + host)


def _fetch(url: str) -> str | None:
    if not is_safe_url(url):
        logger.warning("Target map blocked unsafe URL: %s", url)
        return None
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    if "text/html" not in r.headers.get("Content-Type", "").lower():
        return None
    return r.text


def _extract_links(html: str, base_url: str, host: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        absolute = urljoin(base_url, a["href"])
        if not _same_host(absolute, host):
            continue
        parsed = urlparse(absolute)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        if clean and clean != base_url.rstrip("/"):
            out.append(clean)
    return out


def _extract_visible_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    parts: list[str] = []
    if soup.title and soup.title.string:
        parts.append(soup.title.string.strip())
    md = soup.find("meta", attrs={"name": "description"})
    if md and md.get("content"):
        parts.append(md["content"].strip())
    for tag in soup.find_all(["h1", "h2", "h3"]):
        t = tag.get_text(strip=True)
        if t:
            parts.append(t)
    parts.append(soup.get_text(" ", strip=True))
    return " ".join(parts)


def _normalize(s: str) -> str | None:
    s = re.sub(r"\s+", " ", s).strip(" \t\n.,;:!?-")
    if len(s) < 3 or len(s) > 50:
        return None
    if s.lower() in STOP_TOKENS:
        return None
    if not re.search(r"[A-Za-z]", s):
        return None
    return s


def crawl_target(seed_url: str, host: str) -> str:
    """BFS crawl up to MAX_PAGES within `host`, returning concatenated visible
    text. Hard-capped by TIME_BUDGET_S so we never block a scan for long."""
    if not host or not is_safe_hostname(host):
        return ""
    seed = seed_url if seed_url.startswith("http") else f"https://{seed_url}"
    seed_clean = seed.rstrip("/")
    seen = {seed_clean}
    queue = deque([(seed_clean, 0)])
    texts: list[str] = []
    start = time.monotonic()
    while queue and len(texts) < MAX_PAGES:
        if time.monotonic() - start > TIME_BUDGET_S:
            logger.info("Target map: time budget exhausted at %d pages", len(texts))
            break
        current, depth = queue.popleft()
        html = _fetch(current)
        if not html:
            continue
        texts.append(_extract_visible_text(html))
        if depth >= MAX_DEPTH:
            continue
        for link in _extract_links(html, current, host):
            if link not in seen and len(seen) < MAX_PAGES * 3:
                seen.add(link)
                queue.append((link, depth + 1))
    logger.info("Target map: fetched %d pages from %s in %.1fs", len(texts), host, time.monotonic() - start)
    return "\n\n".join(texts)


def extract_identity_tokens(seed_url: str, identity: dict) -> list[str]:
    """Crawl the target site and return product/brand strings to use as extra
    dork seeds. Excludes tokens already covered by the URL-derived identity
    so we don't issue redundant queries.

    Empty list = "no enrichment" — caller continues with identity-only dorks.
    """
    host = (identity.get("domain") or "").lower()
    text = crawl_target(seed_url, host)
    if not text:
        return []

    entities = _gliner._predict(
        text,
        ["organization", "product name", "brand name"],
        threshold=0.5,
    )
    if not entities:
        return []

    # Identity strings the existing dorks already cover; new tokens that match
    # any of these add no coverage and just burn Serper credits.
    covered = {
        (identity.get("company_name") or "").lower(),
        (identity.get("domain_root") or "").lower(),
        (identity.get("company_slug") or "").lower(),
        (identity.get("domain") or "").lower(),
    }
    covered.discard("")

    tokens: set[str] = set()
    for e in entities:
        norm = _normalize(e.get("text") or "")
        if not norm:
            continue
        low = norm.lower()
        if low in covered:
            continue
        # Skip near-duplicates of identity strings (e.g., "Fortra Inc" vs "Fortra").
        if any(c and (c in low or low in c) for c in covered):
            continue
        tokens.add(norm)
    return sorted(tokens)
