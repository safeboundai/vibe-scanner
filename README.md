# vibe-scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Node 20+](https://img.shields.io/badge/node-20+-green.svg)](https://nodejs.org/)

Discovers and assesses **vibe-coded shadow apps** — internal tools deployed by employees, without IT review, on AI/no-code builders (Lovable, Replit, Base44), JAMstack/serverless hosts (Netlify, Vercel, Cloudflare Pages, Fly.io, Firebase Hosting), ML demo platforms (Hugging Face Spaces, Streamlit Cloud), and quick-prototype platforms (Glitch). Given a single target domain (e.g. `example.com`), it enumerates apps belonging to that organization across all 11 platforms, then probes each app for exposed authentication, hardcoded secrets, Supabase RLS-bypass conditions ([CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757)), and sensitive data classes.

Built for **enterprise red teams** doing authorized shadow-IT discovery against their own organizations.

The CLI streams JSON-line events on stdout. The bundled Node dashboard forwards them as Server-Sent Events to a browser-based terminal UI at `/vibe-scan.html`.

---

## Quick start

```bash
git clone https://github.com/safeboundai/vibe-scanner.git
cd vibe-scanner
cp .env.example .env             # fill in SERPER_API_KEY (required)
docker build -t vibe-scanner .
docker run --rm -p 8080:8080 --env-file .env vibe-scanner
# open http://localhost:8080
```

Without Docker:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd server && npm install && cd ..
cp .env.example .env             # fill in SERPER_API_KEY
PYTHON_BIN=$(pwd)/venv/bin/python (cd server && npm start)
# open http://localhost:8080
```

Or run the CLI directly:

```bash
venv/bin/python -m scans.vibe_scan_cli --domain example.com --name "Example Co"
```

### Test locally

After the image is built, re-run with your local `.env` injected at run time:

```bash
docker run --rm -p 8080:8080 --env-file .env vibe-scanner
```

The container reads `SERPER_API_KEY` (and any other vars) from your `.env` via `--env-file`. The file itself is **not** baked into the image — `.dockerignore` excludes it on purpose so secrets don't leak into a shared registry.

---

## Configuration

All settings come from environment variables (auto-loaded from `.env`). See `.env.example` for the full list.

| Variable | Required | Purpose |
|---|---|---|
| `SERPER_API_KEY` | **yes** | Drives the Google-index dork queries. Get one at [serper.dev](https://serper.dev). |
| `HF_TOKEN` | recommended | Speeds up the first GLiNER model download (~700 MB). |
| `USE_AI` | optional | `true` to enable GPT-4o risk-assessment narratives. Default `false` (rules-engine fallback). |
| `OPENAI_API_KEY` | optional | Required when `USE_AI=true`. |
| `PORT` | optional | Default `8080`. |
| `ALLOWED_ORIGINS` | optional | CORS allowlist (comma-separated). Blank = same-origin only. |
| `SSM_PREFIX` | optional | Look up missing secrets in AWS SSM under this prefix. Requires `pip install vibe-scanner[ssm]`. |

---

## Algorithm

Three sequential phases plus per-app post-processing.

### Phase 0 — Target map (pre-discovery, optional)

**Purpose:** widen the identity-token set fed to the dork generator. URL-derived identity (`example.com` → `Example` / `example`) misses apps named after products rather than the parent organization — e.g. Example Corp's vibe-coded tool for "ProductX" won't surface for `site:vercel.app "example"`.

**Code:** `scans/_target_map.py`

1. BFS crawl the target domain using `requests` + BeautifulSoup. Settings: `MAX_DEPTH=3`, `MAX_PAGES=50`, `TIME_BUDGET_S=20`, `REQUEST_TIMEOUT=8`. The time budget is a hard wall-clock cutoff so a slow or hostile target never blocks a scan.
2. Same-host filter excludes external links and social media at link-extraction time.
3. From each fetched page, pull `<title>`, `<meta name="description">`, `<h1/h2/h3>`, and body text.
4. Run the concatenated text through GLiNER with entity labels `["organization", "product name", "brand name"]` at threshold 0.5.
5. Normalize each span: trim, drop length ≤ 3 or ≥ 50, strip stop tokens (`home`, `about`, `login`, …), require at least one ASCII letter.
6. Filter out tokens already covered by the URL-derived identity, plus sub/superstrings thereof.
7. Return sorted list. Attached to `identity["extra_tokens"]` and used in (a) relevance scoring (+0.2 per match) and (b) one extra `site:{platform} "{token}"` dork per platform.

Skipped entirely with `--no-target-map`. Gracefully degrades to `[]` when GLiNER isn't available.

### Phase 1 — Discovery

**Code:** `scans/vibe_code.py:discover`

For each platform × dork template (× extra token), call Serper's `/search`.

**Dork templates** (11 total):

| Family | Template | Purpose |
|---|---|---|
| Identity | `site:{platform} "{company_name}"` | Direct company-name mentions |
| Identity | `site:{platform} "{domain_root}"` | Bare brand string |
| Identity | `site:{platform} "mailto:{domain}"` | Pages with org-domain mailto links |
| Identity | `site:{platform} "@{domain}"` | Pages mentioning org email addresses |
| Identity | `site:{platform} "{company_slug}-"` | Hostname-style slug prefix |
| Identity | `site:{platform} "{company_slug} "` | Slug as standalone token |
| Intent | `site:{platform} "{domain}" "Supabase"` | Pages with Supabase config + org tie-in |
| Intent | `site:{platform} "{domain}" "firebaseConfig"` | Pages with Firebase config + org tie-in |
| Intent | `site:{platform} "{company_name}" "dashboard"` | Admin/data UIs |
| Intent | `site:{platform} "{company_name}" "admin"` | Admin surfaces |
| Intent | `site:{platform} "{company_name}" "login"` | Auth surfaces |

**Pagination:** loops up to `SERPER_PAGES=2` pages at `num=30`, stopping early when a page returns empty or fewer than `num` results. Per-scan upper bound: 11 dorks × 11 platforms × 2 pages = 242 Serper requests, plus one per extra-token dork × 11 platforms × 2 pages.

**Per-hit filtering:**

1. Drop if hostname matches `TEST_SLUG_PATTERNS` (`^(test|demo|example|my-first|hello-world|untitled)-`, `\b(template|starter|boilerplate)\b`).
2. Compute relevance: +0.5 for full `domain.com` in title/snippet/link, +0.3 for company slug, +0.3 for company name, +0.2 for domain root, +0.2 per extra-token match. Capped at 1.0.
3. Compute hostname match: split the subdomain on `[^a-z0-9]+`, drop generic tokens (`app`, `dev`, `tools`, …), accept if any identity needle is in the resulting token set.
4. Compute text match: full `domain.com` literal in title or snippet.
5. **Keep only if** `relevance ≥ 0.3` **AND** (`host_match` **OR** `text_match`). The second condition is what kills false positives like "company mentioned in passing in a pentest blog."
6. Dedupe by URL keeping the highest-relevance copy.

Return the top `max_apps` (default 20) sorted by relevance descending.

### Phase 2 — Probing

**Code:** `scans/vibe_code.py:probe`. Runs in a 5-worker `ThreadPoolExecutor`.

For each surviving candidate:

1. **HEAD** with 10s timeout, redirects followed. HTTP 401/403 → `auth_status="secured"`. HTTP ≥ 400 → return.
2. **GET** with 10s timeout. If the final URL contains `login` and differs from the request URL → `auth_status="platform_auth"`.
3. Scan response body (≤ first 5000 chars):
   - Password-input regex → `auth_status="trivial"`. Absence + 200 OK → `auth_status="none"`.
   - Hardcoded password / API-key regex → `hardcoded_credentials=True`.
   - Supabase URL regex → `supabase_detected=True`. With an anon-JWT also present, calls `_check_supabase_rls`.
4. **Supabase RLS probe** (CVE-2025-48757): for each guess in `("users","profiles","customers","leads","accounts")`, GET `{supabase_url}/rest/v1/{table}?select=*&limit=1` with the anon JWT. The function asserts `r.request.method == "GET"` defensively — the probe is read-only by construction. Non-empty 200 → `supabase_rls_bypass=True`.
5. **Attribution** — accepts only ownership-grade signals (a bare `domain.com` substring is *not* sufficient — see "service-provider targets" below). Signals in order:
   - `mailto:*@domain` → `signal="mailto:@domain"`
   - `@domain\b` literal → `signal="@domain"`
   - `©/&copy;/&#169;/copyright` within 40 chars of `company_name` → `signal="copyright"`
   - `<link rel="canonical" href="https://domain">` → `signal="canonical"`
   - GLiNER `organization` span overlapping `company_name` → `signal="gliner:organization"` (demoted when "uses" language is present)
   - Hostname-only match (e.g. `acme-crm.vercel.app` for acme.com) → `signal="hostname"` (also demoted by "uses" language)
6. **"Uses" language detection** — regex over the body for `powered by X`, `built with X`, `made with X`, `via X`, `using X`, `integrates with X`, etc. When matched, the page frames the target as a consumed dependency, so the two weakest attribution paths (GLiNER organization span, hostname-only match) are blocked. Strong literals (mailto, @domain) and ownership-grade signals (copyright, canonical) override "uses" language.
7. **SPA fallback** — if attribution still fails AND the body looks like an empty SPA shell, re-fetch via headless Chrome (`scans/_browser.py`) and re-run attribution, credential scan, and Supabase detection against the rendered DOM.

Candidates without `attribution_found=True` are dropped before classification — the CLI emits a `SKIP` phase event for each.

### Classification

**Code:** `scans/vibe_code.py:classify` + `scans/_gliner.py:classify_text`.

1. Strip HTML tags from the snippet.
2. GLiNER with 22 entity labels at threshold 0.4. Input HTML-stripped, capped at 8000 chars, chunked at 1200 chars on sentence boundaries (or force-broken when there's no punctuation) to stay under gliner_medium-v2.1's 384-token per-sentence sequence limit.
3. Map detected labels onto data classes: `{person name, email, phone, address}` → `pii_contact`; `{customer record}` → `crm`; `{employee record, salary}` → `hr`; `{go-to-market, competitive analysis, unreleased product}` → `strategy`; `{budget, vendor contract}` → `finance`; `{medical, health record}` → `healthcare`; `{api key, db connection string}` → `credentials`; `{source code}` → `source_code`.
4. **Fallback when GLiNER unavailable:** regex pass over keyword patterns against the first 6000 chars.
5. `sensitivity_score = min(1.0, 0.2 * len(data_classes))`.

### Severity scoring

| Condition | Severity |
|---|---|
| `supabase_rls_bypass` | **CRITICAL** |
| `auth_status="none"` AND `sensitivity > 0.6` | **CRITICAL** |
| `auth_status="none"` | **HIGH** |
| `auth_status="trivial"` AND `sensitivity > 0.4` | **HIGH** |
| `hardcoded_credentials` | **HIGH** |
| `auth_status="oauth_any"` AND `sensitivity > 0.3` | **MEDIUM** |
| `auth_status="platform_auth"` | **LOW** |
| else | **LOW** |

### Regulatory mapping

Each detected data class maps to relevant regulatory frameworks (e.g. `pii_contact` → `CCPA · GDPR · state breach notification laws`). The joined string is attached as `regulatory_exposure`.

### Known limitation: service-provider targets

The attribution model is calibrated for **product companies** (clear product boundary, rare incidental mentions). For **service-provider targets** — `huggingface.co`, `github.com`, `openai.com`, `stripe.com`, `npmjs.com` — the world is full of third-party apps that legitimately reference them in product context. The ownership-grade rules (strong literals only, "uses" framing demotes weak attribution) cut most of that noise but cannot fully solve it: a third-party tool that ships with a `© Hugging Face` snippet copied from upstream will still slip through. For such targets, prefer a narrower identity (a specific product name as `--name`) and accept lower recall, or use a different tool that walks `*.target-domain` via DNS + cert-transparency logs (out of scope here).

---

## SSE event schema

The CLI emits one JSON object per line on stdout. The Node parent forwards each as an SSE `data:` frame.

```
{"type": "phase",  "label": "...", "detail": "..."}        progress in terminal animation
{"type": "app",    "app":   {url, platform, severity, ...}} per-app probe result, streamed
{"type": "result", "result": {identity, apps, summary}}    final payload after all probes
{"type": "error",  "message": "..."}                       fatal error (e.g. missing API key)
```

Phase labels: `PHASE 0` (target map), `PHASE 1` (discovery), `PHASE 2` (probing), per-platform `Querying`, `SKIP`/`WARN` per candidate, `FILTERED` summary, `SCAN COMPLETE`.

---

## Module layout

```
scans/
  vibe_code.py       ── pipeline (discover, probe, classify, calculate_severity)
  vibe_scan_cli.py   ── CLI wrapper, emits SSE-shaped JSON lines on stdout
  _target_map.py     ── Phase 0: BFS crawl + GLiNER token extraction
  _gliner.py         ── lazy-loaded GLiNER singleton + label maps
  _browser.py        ── headless-Chrome SPA fallback
utils/
  secrets.py         ── env-var first, optional SSM backend
server/
  server.js          ── SSE endpoint /api/vibe-scan, GPT-4o proxy /api/assess
  public/vibe-scan.html  ── dashboard terminal animation
```

---

## Dependencies

- **`requests`, `beautifulsoup4`, `python-dotenv`** — required.
- **`gliner`** — required for high-accuracy classification and attribution. First call downloads `urchade/gliner_medium-v2.1` (~700 MB) into `~/.cache/huggingface/`. Without it, both fall back to regex (lower recall).
- **`selenium`** — required for the SPA-rendering fallback (`scans/_browser.py`). The Dockerfile installs Chrome stable; outside Docker, ensure `google-chrome-stable` is on `PATH` or set `BROWSER_PATH`.
- **`boto3`** — optional (`pip install vibe-scanner[ssm]`). Only needed if you set `SSM_PREFIX` to use AWS SSM as a secret backend.

---

## Ethics & authorization

VibeScan is built for **authorized security testing**: scanning domains you own, or domains where you have explicit written permission from the owner. The Supabase RLS probe is read-only by construction (`assert r.request.method == "GET"`), but discovery-time dorks and SPA-rendering probes generate traffic to third-party platforms — use accordingly. Don't point this at organizations without authorization.

---

## Contributing

Issues and PRs are welcome. For substantial changes, please open an issue first to discuss.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
