"""
VibeScan integration — discovers and assesses vibe-coded shadow apps
deployed on Lovable, Replit, Base44, Netlify, and Vercel.

Implements the v2.0 tech spec (see vibe-code-scanner/vibescan_v2_tech_spec.md):
  §2  Discovery via Serper.dev dork queries (Google index, no GCP setup)
  §3  HTTP HEAD/GET probing for auth status, login forms, hardcoded creds
  §3.2 step 4  Supabase RLS bypass check (CVE-2025-48757) — SELECT-only
  §4  Regex-based data classification (GLiNER swap deferred to v2)
  §5.1  Severity scoring

Credentials are loaded via utils.secrets.get_secret, which checks env vars
first then falls back to AWS SSM Parameter Store under SSM_PREFIX. The
only secret needed is SERPER_API_KEY.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from scans import _browser, _gliner
from utils.network import is_safe_url
from utils.secrets import get_secret


logger = logging.getLogger(__name__)


PLATFORMS = [
    # AI / vibe-coding builders
    "lovable.app",
    "replit.app",
    "base44.app",
    # JAMstack / serverless hosts where free-tier shadow deploys land
    "netlify.app",
    "vercel.app",
    "pages.dev",  # Cloudflare Pages
    "fly.dev",  # Fly.io
    "web.app",  # Firebase Hosting (modern)
    # ML / data-app demo platforms
    "hf.space",  # Hugging Face Spaces
    "streamlit.app",  # Streamlit Community Cloud
    # Quick-prototype platforms
    "glitch.me",  # Glitch
]

DORK_TEMPLATES = [
    # Identity-only — find apps tied to the organization.
    'site:{platform} "{company_name}"',
    'site:{platform} "{domain_root}"',
    'site:{platform} "mailto:{domain}"',
    'site:{platform} "@{domain}"',
    'site:{platform} "{company_slug}-"',
    'site:{platform} "{company_slug} "',
    # Identity + intent — narrow to high-risk surfaces. Tech-leak dorks
    # (Supabase, firebaseConfig) pair with `{domain}` because developers
    # typically embed the company domain near config strings; human-facing
    # surfaces (dashboard/admin/login) pair with `{company_name}` because
    # that's what shows up in UI copy.
    'site:{platform} "{domain}" "Supabase"',
    'site:{platform} "{domain}" "firebaseConfig"',
    'site:{platform} "{company_name}" "dashboard"',
    'site:{platform} "{company_name}" "admin"',
    'site:{platform} "{company_name}" "login"',
]

# Serper bills per request, not per result. Bumping pages multiplies cost
# linearly but is the only way to surface results beyond Google's first page.
SERPER_PAGES = 2

TEST_SLUG_PATTERNS = (
    re.compile(r"^(test|demo|example|my-first|hello-world|untitled)-", re.I),
    re.compile(r"\b(template|starter|boilerplate)\b", re.I),
)

REGEX_API_KEY = re.compile(r"(?i)(api[_-]?key|secret|token)[\s\"':=]+[A-Za-z0-9_\-]{24,}")
REGEX_SUPABASE_URL = re.compile(r"https://([a-z0-9]+)\.supabase\.co", re.I)
REGEX_SUPABASE_ANON = re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")
REGEX_HARDCODED_PWD = re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"']{4,}[\"']")
REGEX_LOGIN_FORM = re.compile(r"<input[^>]+type\s*=\s*[\"']password[\"']", re.I)
REGEX_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
REGEX_PHONE = re.compile(r"\b(?:\+?1[\-.\s]?)?\(?\d{3}\)?[\-.\s]?\d{3}[\-.\s]?\d{4}\b")

DATA_CLASS_KEYWORDS = {
    "pii_contact": (REGEX_EMAIL, REGEX_PHONE),
    "credentials": (REGEX_API_KEY, REGEX_SUPABASE_ANON),
    "crm": (re.compile(r"\b(customer|lead|contact list|account manager|deal|pipeline)\b", re.I),),
    "hr": (re.compile(r"\b(employee|salary|compensation|payroll|onboarding|hiring)\b", re.I),),
    "finance": (re.compile(r"\b(budget|invoice|vendor contract|expense report|p&l)\b", re.I),),
    "healthcare": (re.compile(r"\b(patient|diagnosis|prescription|medical record|phi)\b", re.I),),
    "source_code": (re.compile(r"\b(github\.com/|gitlab\.com/|source code|repo)\b", re.I),),
    "strategy": (re.compile(r"\b(roadmap|launch plan|go.to.market|competitive analysis)\b", re.I),),
}

# Spec §5.3
REGULATORY_MAP = {
    "pii_contact": "CCPA · GDPR · state breach notification laws",
    "crm": "CCPA · GDPR · state breach notification laws",
    "hr": "FCRA · state wage laws · ADA · EEOC obligations",
    "strategy": "Trade secret law · potential SEC MNPI",
    "finance": "SOX · OCC guidance · state financial privacy",
    "healthcare": "HIPAA · HITECH · state health privacy laws",
    "credentials": "Immediate rotation required · supply chain risk",
    "source_code": "Trade secret · OSS license · supply chain risk",
}

SUPABASE_TABLE_GUESSES = ("users", "profiles", "customers", "leads", "accounts")

# Minimum relevance score to keep a candidate. Anything below this is too weak
# a signal to claim the app belongs to the target organization.
MIN_RELEVANCE_SCORE = 0.3

# Generic tokens we ignore when matching company slugs against hostnames. A
# subdomain like "pentest-tools-fym3bzln8" should not match "fortra" just
# because the snippet talks about Fortra products.
GENERIC_SLUG_TOKENS = {
    "app",
    "apps",
    "ai",
    "dev",
    "test",
    "demo",
    "staging",
    "prod",
    "main",
    "preview",
    "site",
    "web",
    "www",
    "tool",
    "tools",
    "internal",
}


def _derive_identity(url: str, name: str | None) -> dict:
    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    host = parsed.hostname or ""
    parts = [p for p in host.split(".") if p]
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    domain_root = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
    company_name = (name or "").strip() or domain_root.title()
    company_slug = re.sub(r"[^a-z0-9]+", "-", company_name.lower()).strip("-") or domain_root
    return {
        "domain": domain,
        "domain_root": domain_root,
        "company_name": company_name,
        "company_slug": company_slug,
    }


def _serper_search(query: str, api_key: str, pages: int = 1) -> list[dict]:
    """Call Serper.dev's /search endpoint across `pages` Google pages and
    return the concatenated `organic` items in rank order. Each item has
    'link', 'title', and 'snippet' keys (same shape Google CSE returned).

    Stops early when a page returns no organic results, returns fewer than
    `num`, or the HTTP call fails — so a target with little Google coverage
    won't burn extra Serper credits on empty pages.
    """
    out: list[dict] = []
    num = 30
    for page in range(1, max(1, pages) + 1):
        try:
            resp = requests.post(
                "https://google.serper.dev/search",
                headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
                json={"q": query, "num": num, "page": page},
                timeout=10,
            )
            if resp.status_code != 200:
                logger.warning("Serper %s: %s", resp.status_code, resp.text[:200])
                break
            organic = resp.json().get("organic") or []
            if not organic:
                break
            out.extend(organic)
            if len(organic) < num:
                break
        except requests.RequestException as e:
            logger.warning("Serper request failed: %s", e)
            break
    return out


def _score_relevance(item: dict, identity: dict) -> float:
    blob = " ".join((item.get("title", ""), item.get("snippet", ""), item.get("link", ""))).lower()
    score = 0.0
    if identity["domain"].lower() in blob:
        score += 0.5
    if identity["company_slug"].lower() in blob:
        score += 0.3
    if identity["company_name"].lower() in blob:
        score += 0.3
    if identity["domain_root"].lower() in blob:
        score += 0.2
    # Each extra target-mapped token (product/brand name from the crawl) adds
    # a smaller bonus — it confirms relevance but is weaker than a full
    # domain or slug match.
    for token in identity.get("extra_tokens", []):
        if token and token.lower() in blob:
            score += 0.2
    return min(score, 1.0)


def _hostname_matches_identity(host: str, identity: dict, platform: str) -> bool:
    """True when the URL hostname itself contains a company identifier.

    For `acme-crm.vercel.app` and identity `acme`, the subdomain tokens are
    {"acme", "crm"} → match. For `pentest-tools-fym3bzln8-pentest-tools.vercel.app`
    and identity `fortra`, subdomain tokens never contain "fortra" → no match.
    Generic tokens like "app", "dev", "tools" can't cause a match on their own.
    """
    host = (host or "").lower()
    if not host:
        return False
    # Strip the platform suffix (e.g. ".vercel.app") to isolate the subdomain.
    subdomain = host
    if subdomain.endswith("." + platform):
        subdomain = subdomain[: -(len(platform) + 1)]
    elif subdomain.endswith(platform):
        subdomain = subdomain[: -len(platform)].rstrip(".")
    tokens = {t for t in re.split(r"[^a-z0-9]+", subdomain) if t and t not in GENERIC_SLUG_TOKENS}
    needles = {
        identity["company_slug"].lower(),
        identity["domain_root"].lower(),
    }
    needles = {n for n in needles if n and n not in GENERIC_SLUG_TOKENS and len(n) >= 3}
    return any(n in tokens or any(n in t or t in n for t in tokens) for n in needles)


def _text_matches_identity(item: dict, identity: dict) -> bool:
    """True when the search hit's title/snippet contains the full `domain.com`
    literal — a much stronger signal than the company name alone, which can
    incidentally show up in pentest/security content for big vendors.
    """
    blob = " ".join((item.get("title", ""), item.get("snippet", ""))).lower()
    full_domain = identity["domain"].lower()
    return bool(full_domain) and full_domain in blob


def discover(identity: dict, platforms: list[str], max_apps: int) -> list[dict]:
    api_key = get_secret("SERPER_API_KEY")
    if not api_key:
        logger.info("VibeScan discovery skipped: SERPER_API_KEY not configured")
        return []

    candidates: dict[str, dict] = {}
    extra_tokens = identity.get("extra_tokens", []) or []
    for platform in platforms:
        # Identity-templated dorks plus one bare dork per target-mapped token.
        # Token dorks pair the platform with a brand/product string lifted
        # from the target's own site — surfaces apps named after products
        # rather than the parent organization.
        platform_queries = [t.format(platform=platform, **identity) for t in DORK_TEMPLATES]
        platform_queries.extend(f'site:{platform} "{token}"' for token in extra_tokens)
        for query in platform_queries:
            for item in _serper_search(query, api_key, pages=SERPER_PAGES):
                link = (item.get("link") or "").lower().rstrip("/")
                if not link or platform not in link:
                    continue
                host = urlparse(link).hostname or ""
                if any(p.search(host) for p in TEST_SLUG_PATTERNS):
                    continue

                relevance = _score_relevance(item, identity)
                host_match = _hostname_matches_identity(host, identity, platform)
                text_match = _text_matches_identity(item, identity)

                # A candidate must (a) be relevant enough overall, AND (b) have
                # either a hostname tied to the organization or the full
                # domain.com literal appearing in the search snippet. This
                # eliminates the false positives where unrelated security/
                # pentest content happens to mention the company name.
                if relevance < MIN_RELEVANCE_SCORE:
                    continue
                if not (host_match or text_match):
                    logger.debug(
                        "VibeScan dropped %s — weak hit (relevance=%.2f, host_match=%s, text_match=%s)",
                        link,
                        relevance,
                        host_match,
                        text_match,
                    )
                    continue

                existing = candidates.get(link)
                if existing is None or relevance > existing["relevance_score"]:
                    candidates[link] = {
                        "url": link,
                        "platform": platform.replace(".app", ""),
                        "discovery_method": "dork_serper",
                        "discovery_query": query,
                        "relevance_score": relevance,
                        "hostname_match": host_match,
                        "title": item.get("title"),
                        "snippet": item.get("snippet"),
                    }
    return sorted(candidates.values(), key=lambda a: a["relevance_score"], reverse=True)[:max_apps]


def _check_supabase_rls(supabase_url: str, anon_key: str) -> bool:
    """SELECT-only probe of Supabase REST. CVE-2025-48757.

    Never issues any verb other than GET. The assertion is defensive — if a
    future refactor sneaks in a non-GET call, this raises rather than hits
    the third-party endpoint with a mutating request.
    """
    if not is_safe_url(supabase_url):
        logger.warning("VibeScan blocked unsafe Supabase URL: %s", supabase_url)
        return False

    for table in SUPABASE_TABLE_GUESSES:
        try:
            r = requests.get(
                f"{supabase_url}/rest/v1/{table}",
                params={"select": "*", "limit": "1"},
                headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}"},
                timeout=8,
            )
            assert r.request.method == "GET", "Supabase RLS probe must be GET-only"
            if r.status_code == 200 and r.text and r.text.strip() not in ("[]", ""):
                return True
        except requests.RequestException:
            continue
    return False


def _check_attribution(body: str, identity: dict) -> dict:
    """Look for evidence the page actually belongs to the target organization.

    Accepts only ownership-grade signals: a company-domain email (mailto: or
    @domain), an ownership copyright string, or a canonical link pointing
    back to the target domain. A bare `domain.com` literal in the body is
    NOT sufficient — for service-provider targets (huggingface.co, github.com,
    stripe.com) that string appears on every third-party page that links to
    a product, which would attribute every consumer back to the provider.

    Also detects "uses" framing — `powered by X`, `built with X`, `via X` —
    and reports it as `uses_language`. Weak signals (GLiNER organization
    spans, hostname matches in `probe()`) are demoted to no-match when uses
    language is present, since those signals can't tell ownership from
    consumption on their own.
    """
    empty = {"attribution_found": False, "attribution_signal": "", "uses_language": False}
    if not body:
        return empty
    text = body[:200_000]  # cap to avoid huge pages dominating regex
    domain = identity["domain"].lower()
    company_name = (identity.get("company_name") or "").strip()

    uses_language = False
    if company_name:
        uses_pat = re.compile(
            rf"\b(?:powered\s+by|built\s+with|made\s+with|via|using|integrates?\s+with|"
            rf"wrapper\s+for|client\s+for|api\s+for|interface\s+(?:for|to)|on\s+top\s+of|"
            rf"thanks\s+to|inspired\s+by|alternative\s+to)\s+{re.escape(company_name)}\b",
            re.I,
        )
        uses_language = bool(uses_pat.search(text))

    # Strong literal signals — sufficient even when "uses" language is also
    # present (e.g. a HF blog post that says "powered by Hugging Face" still
    # belongs to HF if it has an @huggingface.co email in the footer).
    mail_pat = re.compile(rf"mailto:[^\"'>\s]*@{re.escape(domain)}", re.I)
    at_pat = re.compile(rf"@{re.escape(domain)}\b", re.I)
    if mail_pat.search(text):
        return {"attribution_found": True, "attribution_signal": "mailto:@domain", "uses_language": uses_language}
    if at_pat.search(text):
        return {"attribution_found": True, "attribution_signal": "@domain", "uses_language": uses_language}

    # Ownership-grade signals — the page asserts the target owns the content.
    if company_name:
        copyright_pat = re.compile(
            rf"(?:©|&copy;|&#169;|copyright)[^.<>]{{0,40}}?{re.escape(company_name)}",
            re.I,
        )
        if copyright_pat.search(text):
            return {"attribution_found": True, "attribution_signal": "copyright", "uses_language": uses_language}
    canonical_pat = re.compile(
        rf'<link[^>]+rel\s*=\s*["\']canonical["\'][^>]+href\s*=\s*["\']https?://(?:www\.)?{re.escape(domain)}',
        re.I,
    )
    if canonical_pat.search(text):
        return {"attribution_found": True, "attribution_signal": "canonical", "uses_language": uses_language}

    # GLiNER fallback. Demoted to no-match when the page has "uses" framing —
    # a Hugging-Face organization span next to "powered by Hugging Face" is a
    # reference, not an ownership claim.
    if not uses_language:
        org_hit = _gliner.find_organization(text, company_name)
        if org_hit:
            return {
                "attribution_found": True,
                "attribution_signal": "gliner:organization",
                "uses_language": uses_language,
            }

    return {"attribution_found": False, "attribution_signal": "", "uses_language": uses_language}


def probe(app: dict, identity: dict | None = None) -> dict:
    """Spec §3.2 — HEAD, GET, login/auth detection, credential scan, Supabase RLS.

    When `identity` is provided, also runs an attribution check: scans the
    fetched HTML for a company-domain email or the domain string itself. Apps
    without attribution are flagged for the caller to filter out.
    """
    url = app["url"]
    if not is_safe_url(url):
        return {
            **app,
            "reachable": False,
            "http_status": 0,
            "auth_status": "unknown",
            "auth_detail": "Blocked: unsafe URL (SSRF protection)",
            "supabase_detected": False,
            "supabase_rls_bypass": False,
            "hardcoded_credentials": False,
            "attribution_found": False,
            "attribution_signal": "",
            "raw_html_snippet": "",
        }

    out = {
        **app,
        "reachable": False,
        "http_status": 0,
        "auth_status": "unknown",
        "auth_detail": "",
        "supabase_detected": False,
        "supabase_rls_bypass": False,
        "hardcoded_credentials": False,
        "attribution_found": False,
        "attribution_signal": "",
        "raw_html_snippet": "",
    }

    try:
        head = requests.head(url, timeout=10, allow_redirects=True)
        out["http_status"] = head.status_code
        out["reachable"] = True
        if head.status_code in (401, 403):
            out["auth_status"] = "secured"
            out["auth_detail"] = f"HTTP {head.status_code} on HEAD — auth required"
            return out
        if head.status_code >= 400:
            out["auth_detail"] = f"HTTP {head.status_code}"
            return out
    except requests.RequestException as e:
        out["auth_detail"] = f"HEAD failed: {e.__class__.__name__}"
        return out

    try:
        get = requests.get(url, timeout=10, allow_redirects=True)
        out["http_status"] = get.status_code
        body = get.text or ""
        out["raw_html_snippet"] = body[:5000]

        if get.url != url and "login" in get.url.lower():
            out["auth_status"] = "platform_auth"
            out["auth_detail"] = f"Redirected to login: {get.url}"
            return out

        has_login_form = bool(REGEX_LOGIN_FORM.search(body))
        if get.status_code == 200 and not has_login_form:
            out["auth_status"] = "none"
            out["auth_detail"] = "200 OK · no login form · open access"
        elif has_login_form:
            out["auth_status"] = "trivial"
            out["auth_detail"] = "Login form present — auth strength not verified by passive probe"

        if REGEX_HARDCODED_PWD.search(body) or REGEX_API_KEY.search(body):
            out["hardcoded_credentials"] = True

        sb = REGEX_SUPABASE_URL.search(body)
        anon = REGEX_SUPABASE_ANON.search(body)
        if sb:
            out["supabase_detected"] = True
            if anon:
                out["supabase_rls_bypass"] = _check_supabase_rls(sb.group(0), anon.group(0))

        if identity:
            attr = _check_attribution(body, identity)
            out["attribution_found"] = attr["attribution_found"]
            out["attribution_signal"] = attr["attribution_signal"]
            # A hostname match (e.g. acme-crm.vercel.app for acme.com) is on
            # its own enough evidence — UNLESS the page frames the target as a
            # consumed dependency. `huggingface-widgets.netlify.app` looks
            # like a HF subdomain by hostname, but the body says "Hugging
            # Face models" not "© Hugging Face" — so uses_language gates it.
            if not out["attribution_found"] and app.get("hostname_match") and not attr.get("uses_language", False):
                out["attribution_found"] = True
                out["attribution_signal"] = "hostname"

            # SPA fallback: vibe-coded apps on Lovable/Vercel/Replit are
            # almost always client-rendered. If the requests-only body looks
            # like an empty shell, re-fetch via headless Chromium and re-run
            # both attribution and content classification on the rendered DOM.
            if not out["attribution_found"] and _browser.looks_like_spa_shell(body):
                rendered = _browser.render(url)
                if rendered:
                    out["raw_html_snippet"] = rendered[:50_000]
                    attr2 = _check_attribution(rendered, identity)
                    if attr2["attribution_found"]:
                        out["attribution_found"] = True
                        out["attribution_signal"] = f"rendered:{attr2['attribution_signal']}"
                    out["browser_rendered"] = True
                    # Re-run cred + supabase checks against the rendered body
                    # so SPAs that inject keys at runtime don't get missed.
                    if REGEX_HARDCODED_PWD.search(rendered) or REGEX_API_KEY.search(rendered):
                        out["hardcoded_credentials"] = True
                    sb2 = REGEX_SUPABASE_URL.search(rendered)
                    anon2 = REGEX_SUPABASE_ANON.search(rendered)
                    if sb2 and not out["supabase_detected"]:
                        out["supabase_detected"] = True
                        if anon2:
                            out["supabase_rls_bypass"] = _check_supabase_rls(sb2.group(0), anon2.group(0))
    except requests.RequestException as e:
        out["auth_detail"] = f"GET failed: {e.__class__.__name__}"

    return out


def classify(html: str) -> dict:
    text = re.sub(r"<[^>]+>", " ", html or "")
    # GLiNER first; falls back to regex when unavailable or on inference error.
    gliner_classes = _gliner.classify_text(text)
    if gliner_classes is not None:
        classes = gliner_classes
    else:
        snippet = text[:6000]
        classes = [cls for cls, patterns in DATA_CLASS_KEYWORDS.items() if any(p.search(snippet) for p in patterns)]
    return {"data_classes": classes, "sensitivity_score": min(1.0, 0.2 * len(classes))}


def calculate_severity(probe_result: dict, classification: dict) -> str:
    """Spec §5.1."""
    if probe_result.get("supabase_rls_bypass"):
        return "CRITICAL"
    auth = probe_result.get("auth_status", "unknown")
    sens = classification.get("sensitivity_score", 0)
    # Found via dork query = by definition indexed.
    if auth == "none" and sens > 0.6:
        return "CRITICAL"
    if auth == "none":
        return "HIGH"
    if auth == "trivial" and sens > 0.4:
        return "HIGH"
    if probe_result.get("hardcoded_credentials"):
        return "HIGH"
    if auth == "oauth_any" and sens > 0.3:
        return "MEDIUM"
    if auth == "platform_auth":
        return "LOW"
    return "LOW"


def run_vibe_scan(
    url: str,
    company_name: str | None = None,
    max_apps: int = 20,
    platforms: list[str] | None = None,
) -> dict:
    platforms = platforms or PLATFORMS
    identity = _derive_identity(url, company_name)
    discovery_available = bool(get_secret("SERPER_API_KEY"))

    if not discovery_available:
        return {
            "identity": identity,
            "apps": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "discovery_available": False,
        }

    apps = discover(identity, platforms, max_apps)
    results = []
    if apps:
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(probe, app, identity): app for app in apps}
            for fut in as_completed(futures):
                try:
                    p = fut.result()
                    # Filter out apps with no verifiable attribution to the
                    # target org. Discovery can return false positives where a
                    # page mentions the company name in passing; without an
                    # @domain email, mailto, or hostname match, we can't
                    # credibly claim the app belongs to them.
                    if not p.get("attribution_found"):
                        logger.info("VibeScan filtered (no attribution): %s", p.get("url"))
                        continue
                    c = classify(p.get("raw_html_snippet", ""))
                    p["data_classes"] = c["data_classes"]
                    p["sensitivity_score"] = c["sensitivity_score"]
                    p["severity"] = calculate_severity(p, c)
                    regs = sorted({REGULATORY_MAP[k] for k in c["data_classes"] if k in REGULATORY_MAP})
                    p["regulatory_exposure"] = " · ".join(regs)
                    # Drop the heavy raw_html_snippet from the returned payload.
                    p.pop("raw_html_snippet", None)
                    results.append(p)
                except Exception:
                    logger.exception("VibeScan probe failed")

    summary = {
        "critical": sum(1 for r in results if r["severity"] == "CRITICAL"),
        "high": sum(1 for r in results if r["severity"] == "HIGH"),
        "medium": sum(1 for r in results if r["severity"] == "MEDIUM"),
        "low": sum(1 for r in results if r["severity"] == "LOW"),
        "total": len(results),
    }
    return {
        "identity": identity,
        "apps": results,
        "summary": summary,
        "discovery_available": True,
    }
