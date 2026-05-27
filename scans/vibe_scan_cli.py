"""
CLI wrapper for the /vibe-scan.html dashboard's SSE endpoint.

Streams JSON-line events on stdout so the Node parent can forward them as
Server-Sent Events to the browser. Each line is a complete JSON object:

  {"type": "phase", "label": "...", "detail": "..."}      progress in terminal
  {"type": "app",   "app":   {...}}                       per-app probe result
  {"type": "result","result":{summary, apps, identity}}   final payload
  {"type": "error", "message": "..."}                     fatal error

Usage:
  python -m scans.vibe_scan_cli --domain example.com [--name "Example Co"]
"""

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from scans import _target_map
from scans.vibe_code import PLATFORMS, REGULATORY_MAP, _derive_identity, calculate_severity, classify, discover, probe
from utils.secrets import get_secret


def emit(event: dict) -> None:
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--name", default=None)
    parser.add_argument("--max-apps", type=int, default=20)
    parser.add_argument(
        "--no-target-map",
        action="store_true",
        help="Skip the pre-discovery target-site crawl that mines extra product/brand tokens.",
    )
    args = parser.parse_args()

    domain_regex = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
    if not domain_regex.match(args.domain):
        emit({"type": "error", "message": f"Invalid domain: {args.domain}"})
        return 1

    if not get_secret("SERPER_API_KEY"):
        emit(
            {
                "type": "error",
                "message": (
                    "Discovery engine not configured — SERPER_API_KEY is missing. "
                    "Set it in your environment or .env file. Get a key at https://serper.dev."
                ),
            }
        )
        return 1

    identity = _derive_identity(args.domain, args.name)

    if not args.no_target_map:
        emit(
            {
                "type": "phase",
                "label": "▶ PHASE 0",
                "detail": f"Target map — crawling {identity['domain']} for product/brand tokens",
            }
        )
        try:
            tokens = _target_map.extract_identity_tokens(args.domain, identity)
        except Exception as e:
            tokens = []
            emit(
                {
                    "type": "phase",
                    "label": "  WARN",
                    "detail": f"target map failed: {e.__class__.__name__}",
                }
            )
        if tokens:
            identity["extra_tokens"] = tokens
            emit(
                {
                    "type": "phase",
                    "label": "✓ TARGET MAP",
                    "detail": f"+{len(tokens)} extra token(s): {', '.join(tokens[:5])}"
                    + (f" +{len(tokens) - 5} more" if len(tokens) > 5 else ""),
                }
            )
        else:
            emit({"type": "phase", "label": "  TARGET MAP", "detail": "no extra tokens extracted"})

    emit(
        {
            "type": "phase",
            "label": "▶ PHASE 1",
            "detail": f"Domain discovery — {identity['domain']}",
        }
    )

    for platform in PLATFORMS:
        emit(
            {
                "type": "phase",
                "label": "  Querying",
                "detail": f"site:{platform} \"{identity['company_name']}\"",
            }
        )

    apps = discover(identity, PLATFORMS, args.max_apps)
    emit(
        {
            "type": "phase",
            "label": "✓ DISCOVERY",
            "detail": f"Found {len(apps)} candidate app(s) across {len(PLATFORMS)} platforms",
        }
    )

    if not apps:
        emit(
            {
                "type": "result",
                "result": {
                    "identity": identity,
                    "apps": [],
                    "summary": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "total": 0,
                    },
                },
            }
        )
        return 0

    emit(
        {
            "type": "phase",
            "label": "▶ PHASE 2",
            "detail": f"Authentication probing ({len(apps)} candidates)",
        }
    )

    results = []
    filtered_no_attribution = 0
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(probe, app, identity): app for app in apps}
        for fut in as_completed(futures):
            try:
                p = fut.result()
                if not p.get("attribution_found"):
                    filtered_no_attribution += 1
                    emit(
                        {
                            "type": "phase",
                            "label": "  SKIP",
                            "detail": f"no attribution to {identity['domain']} → {p.get('url', '')}",
                        }
                    )
                    continue
                c = classify(p.get("raw_html_snippet", ""))
                p["data_classes"] = c["data_classes"]
                p["sensitivity_score"] = c["sensitivity_score"]
                p["severity"] = calculate_severity(p, c)
                regs = sorted({REGULATORY_MAP[k] for k in c["data_classes"] if k in REGULATORY_MAP})
                p["regulatory_exposure"] = " · ".join(regs)
                p.pop("raw_html_snippet", None)
                emit({"type": "app", "app": p})
                results.append(p)
            except Exception as e:
                emit(
                    {
                        "type": "phase",
                        "label": "  WARN",
                        "detail": f"probe failed: {e.__class__.__name__}",
                    }
                )

    if filtered_no_attribution:
        emit(
            {
                "type": "phase",
                "label": "  FILTERED",
                "detail": f"{filtered_no_attribution} candidate(s) dropped — no attribution to {identity['domain']}",
            }
        )

    summary = {
        "critical": sum(1 for r in results if r["severity"] == "CRITICAL"),
        "high": sum(1 for r in results if r["severity"] == "HIGH"),
        "medium": sum(1 for r in results if r["severity"] == "MEDIUM"),
        "low": sum(1 for r in results if r["severity"] == "LOW"),
        "total": len(results),
    }
    emit(
        {
            "type": "phase",
            "label": "✓ SCAN COMPLETE",
            "detail": (
                f"{summary['total']} apps · {summary['critical']} CRITICAL · "
                f"{summary['high']} HIGH · {summary['medium']} MED · {summary['low']} LOW"
            ),
        }
    )
    emit({"type": "result", "result": {"identity": identity, "apps": results, "summary": summary}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
