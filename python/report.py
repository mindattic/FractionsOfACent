"""
HTML report generator for findings.json.

Reads the metadata-only records and emits a self-contained HTML file
(no external assets, no JavaScript). No raw API keys appear — each
record is represented only by the SHA-256 and the 16-char scheme
prefix already stored in findings.json.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROVIDER_LABELS = {
    "anthropic": "Anthropic",
    "openai": "OpenAI (project)",
    "openai-legacy": "OpenAI (legacy)",
    "google-gemini": "Google Gemini",
}


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _card(label: str, value) -> str:
    return (
        f'<div class="card"><div class="label">{_e(label)}</div>'
        f'<div class="value">{_e(value)}</div></div>'
    )


def _bar_row(label: str, n: int, max_n: int) -> str:
    pct = (n / max_n) * 100 if max_n else 0
    return (
        f"<tr><td>{_e(label)}</td>"
        f'<td class="num">{_e(n)}</td>'
        f'<td class="barcell"><div class="bar"><div style="width:{pct:.1f}%"></div></div></td></tr>'
    )


def _finding_row(f: dict) -> str:
    provider = _e(f.get("provider", ""))
    sha = f.get("key_sha256") or ""
    detected = (f.get("detected_at_utc") or "")[:19].replace("T", " ")
    return (
        "<tr>"
        f'<td><span class="pill {provider}">{provider}</span></td>'
        f'<td>{_e(f.get("model_hint") or "—")}</td>'
        f'<td><a href="{_e(f.get("repo_html_url", ""))}" target="_blank" rel="noopener">'
        f"{_e(f.get('repo_full_name'))}</a></td>"
        f'<td>{_e(f.get("author_login") or "—")}</td>'
        f'<td><a class="mono" href="{_e(f.get("file_html_url", ""))}" target="_blank" rel="noopener">'
        f'<span class="truncate">{_e(f.get("file_path"))}</span></a></td>'
        f'<td class="mono">{_e(f.get("key_prefix"))}…</td>'
        f'<td class="num mono">{_e(f.get("key_length"))}</td>'
        f'<td class="mono" title="{_e(sha)}">{_e(sha[:12])}…</td>'
        f'<td class="mono">{_e(detected)}</td>'
        "</tr>"
    )


def render(findings: list[dict]) -> str:
    total = len(findings)
    by_provider = Counter(f.get("provider", "?") for f in findings)
    by_model = Counter(f.get("model_hint") or "(unknown)" for f in findings)
    by_author = Counter(f.get("author_login") or "(unknown)" for f in findings)
    unique_repos = {f.get("repo_full_name") for f in findings if f.get("repo_full_name")}
    unique_keys = {f.get("key_sha256") for f in findings if f.get("key_sha256")}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tiles = (
        _card("Findings", total)
        + _card("Unique keys", len(unique_keys))
        + _card("Unique repos", len(unique_repos))
        + "".join(
            _card(PROVIDER_LABELS.get(p, p), n)
            for p, n in by_provider.most_common()
        )
    )

    model_max = max(by_model.values(), default=1)
    model_rows = "".join(
        _bar_row(m, n, model_max) for m, n in by_model.most_common(20)
    )
    author_max = max(by_author.values(), default=1)
    author_rows = "".join(
        _bar_row(a, n, author_max) for a, n in by_author.most_common(15)
    )

    table_rows = "".join(
        _finding_row(f)
        for f in sorted(
            findings, key=lambda x: x.get("detected_at_utc") or "", reverse=True
        )
    )

    empty_row = '<tr><td colspan="{n}" class="muted">no data</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FractionsOfAPenny — Findings Report</title>
<style>
  :root {{ color-scheme: light dark;
           --bg:#0b0d10; --fg:#e6e6e6; --card:#151a20; --muted:#8a9099;
           --accent:#6ea8fe; --warn:#f4a261; --border:#252a31; }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg:#fafbfc; --fg:#1a1f24; --card:#fff; --muted:#5a6470;
             --accent:#0a66c2; --warn:#b35900; --border:#e3e7eb; }}
  }}
  html,body {{ margin:0; padding:0; }}
  body {{ font:14px/1.5 -apple-system,"Segoe UI",Inter,system-ui,sans-serif;
         background:var(--bg); color:var(--fg); }}
  header {{ padding:24px 32px; border-bottom:1px solid var(--border); }}
  h1 {{ margin:0 0 4px; font-size:20px; font-weight:600; }}
  .subtitle {{ color:var(--muted); font-size:13px; }}
  main {{ padding:24px 32px; max-width:1400px; margin:0 auto; }}
  section {{ margin-bottom:32px; }}
  section h2 {{ font-size:11px; font-weight:600; margin:0 0 12px;
                color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }}
  .card {{ background:var(--card); border:1px solid var(--border);
          border-radius:8px; padding:12px 14px; }}
  .card .label {{ color:var(--muted); font-size:11px; text-transform:uppercase;
                   letter-spacing:.05em; }}
  .card .value {{ font-size:22px; font-weight:600; margin-top:2px; }}
  table {{ border-collapse:collapse; width:100%; background:var(--card);
           border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
  th,td {{ padding:8px 10px; text-align:left; border-bottom:1px solid var(--border);
          vertical-align:middle; font-size:13px; }}
  th {{ background:color-mix(in srgb,var(--card) 40%,var(--border));
        font-weight:600; font-size:11px; text-transform:uppercase;
        letter-spacing:.05em; color:var(--muted); }}
  td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.barcell {{ width:45%; }}
  tr:last-child td {{ border-bottom:none; }}
  tbody tr:hover {{ background:color-mix(in srgb,var(--accent) 6%,transparent); }}
  a {{ color:var(--accent); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  code, .mono {{ font:12px/1.4 "SF Mono","JetBrains Mono",Consolas,monospace;
                 color:var(--muted); }}
  .truncate {{ display:inline-block; max-width:320px; overflow:hidden;
               text-overflow:ellipsis; white-space:nowrap; vertical-align:bottom; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:999px;
          background:color-mix(in srgb,var(--accent) 16%,transparent);
          color:var(--accent); font-size:11px; font-weight:600;
          text-transform:uppercase; letter-spacing:.04em; }}
  .pill.anthropic {{ background:color-mix(in srgb,#c96442 18%,transparent); color:#c96442; }}
  .pill.openai {{ background:color-mix(in srgb,#10a37f 18%,transparent); color:#10a37f; }}
  .pill.openai-legacy {{ background:color-mix(in srgb,var(--warn) 18%,transparent); color:var(--warn); }}
  .pill.google-gemini {{ background:color-mix(in srgb,#4285f4 18%,transparent); color:#4285f4; }}
  .bar {{ background:var(--border); border-radius:3px; height:8px; width:100%; overflow:hidden; }}
  .bar > div {{ background:var(--accent); height:100%; }}
  .banner {{ background:color-mix(in srgb,var(--warn) 12%,transparent);
             color:var(--warn);
             border:1px solid color-mix(in srgb,var(--warn) 40%,transparent);
             border-radius:8px; padding:10px 14px; margin-bottom:24px; font-size:13px; }}
  .split {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  @media (max-width:900px) {{ .split {{ grid-template-columns:1fr; }} }}
  .muted {{ color:var(--muted); }}
</style>
</head>
<body>
<header>
  <h1>FractionsOfAPenny — Leaked-Credential Prevalence</h1>
  <div class="subtitle">Metadata-only research dataset · generated {_e(generated)} · {total} findings</div>
</header>
<main>
  <div class="banner">Non-retention: no raw API keys appear in this report. Each key is represented only by a SHA-256 hash and a 16-char scheme prefix.</div>

  <section>
    <h2>Summary</h2>
    <div class="grid">{tiles}</div>
  </section>

  <section>
    <h2>Distribution</h2>
    <div class="split">
      <div>
        <table>
          <thead><tr><th>Model</th><th class="num">Count</th><th>Share</th></tr></thead>
          <tbody>{model_rows or empty_row.format(n=3)}</tbody>
        </table>
      </div>
      <div>
        <table>
          <thead><tr><th>Author</th><th class="num">Count</th><th>Share</th></tr></thead>
          <tbody>{author_rows or empty_row.format(n=3)}</tbody>
        </table>
      </div>
    </div>
  </section>

  <section>
    <h2>Findings ({total})</h2>
    <table>
      <thead><tr>
        <th>Provider</th><th>Model</th><th>Repo</th><th>Author</th><th>File</th>
        <th>Prefix</th><th class="num">Len</th><th>SHA-256</th><th>Detected (UTC)</th>
      </tr></thead>
      <tbody>{table_rows or empty_row.format(n=9)}</tbody>
    </table>
  </section>
</main>
</body>
</html>
"""


def write(findings: list[dict], out_path: Path) -> Path:
    html_path = out_path.with_suffix(".htm")
    html_path.write_text(render(findings), encoding="utf-8")
    return html_path
