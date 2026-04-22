"""
Responsible-disclosure helper.

For each finding, prints the canonical intake channel to report the leak
so the provider can revoke the key. This tool does NOT submit the key
(we don't have it — by design). It opens a browser/links to the
file so the provider's secret-scanning or abuse team can retrieve and
revoke it through their own tooling.

References:
  - Anthropic:     https://support.anthropic.com/  (security@anthropic.com)
  - OpenAI:        https://openai.com/security/  (disclosure@openai.com)
  - Google AI:     https://cloud.google.com/support/docs/issue-trackers
  - GitHub:        already runs secret scanning for these providers;
                   push protection auto-revokes on detection.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

INTAKE = {
    "anthropic": "security@anthropic.com",
    "openai": "disclosure@openai.com",
    "openai-legacy": "disclosure@openai.com",
    "google-gemini": "https://cloud.google.com/support/docs/issue-trackers",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", type=Path)
    args = parser.parse_args()

    records = json.loads(args.findings.read_text(encoding="utf-8"))
    by_provider: dict[str, list[dict]] = {}
    for r in records:
        by_provider.setdefault(r["provider"], []).append(r)

    for provider, items in by_provider.items():
        intake = INTAKE.get(provider, "(no intake on file)")
        print(f"\n=== {provider} — report to: {intake} ({len(items)} findings) ===")
        for r in items:
            print(
                f"  {r['repo_full_name']}  file={r['file_path']}  "
                f"sha256={r['key_sha256'][:16]}…  url={r['file_html_url']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
