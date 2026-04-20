"""Standalone HTML report generator for campaign results."""

import html
import json
import logging
import math
from pathlib import Path

from volte_mutation_fuzzer.campaign.contracts import (
    CampaignResult,
    CampaignSummary,
    CaseResult,
)

logger = logging.getLogger(__name__)

_VERDICT_COLORS: dict[str, str] = {
    "normal": "#4caf50",
    "suspicious": "#ff9800",
    "timeout": "#9e9e9e",
    "crash": "#f44336",
    "stack_failure": "#e91e63",
    "infra_failure": "#795548",
    "unknown": "#607d8b",
    "setup_failed": "#b0bec5",
}

_VERDICT_ORDER: tuple[str, ...] = (
    "normal",
    "suspicious",
    "timeout",
    "crash",
    "stack_failure",
    "infra_failure",
    "unknown",
)

_INTERESTING_VERDICTS: frozenset[str] = frozenset(
    {"crash", "stack_failure", "suspicious"}
)


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _pct(count: int, total: int) -> float:
    if total == 0:
        return 0.0
    return count * 100.0 / total


def _context_lines(case: CaseResult) -> list[str]:
    lines: list[str] = []
    for key, label in (("adb_warning", "ADB warning"), ("ios_warning", "iOS warning")):
        value = case.details.get(key)
        if not isinstance(value, dict):
            continue
        text = str(value.get("matched_line") or value.get("matched_pattern") or "").strip()
        if not text:
            continue
        lines.append(f"{label}: {text}")
    return lines


# ---------------------------------------------------------------------------
# SVG helpers
# ---------------------------------------------------------------------------


def _svg_donut(summary: CampaignSummary, size: int = 200) -> str:
    """Render a donut chart as inline SVG."""
    total = summary.total
    if total == 0:
        return '<svg width="200" height="200"></svg>'

    cx, cy, r = size // 2, size // 2, size // 2 - 20
    circumference = 2 * math.pi * r
    parts: list[str] = []
    parts.append(f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">')

    offset = 0.0
    for v in _VERDICT_ORDER:
        count = getattr(summary, v, 0)
        if count == 0:
            continue
        dash = circumference * count / total
        gap = circumference - dash
        color = _VERDICT_COLORS.get(v, "#ccc")
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{color}" stroke-width="30" '
            f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" />'
        )
        offset += dash

    # Center text
    parts.append(
        f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" '
        f'font-size="24" font-weight="bold" fill="#333">{total}</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def _svg_timeline(cases: list[CaseResult], width: int = 800, height: int = 120) -> str:
    """Render a verdict timeline as inline SVG scatter plot."""
    if not cases:
        return ""

    n = len(cases)
    margin_x, margin_y = 40, 20
    plot_w = width - 2 * margin_x
    plot_h = height - 2 * margin_y

    parts: list[str] = []
    parts.append(f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">')

    # X axis
    parts.append(
        f'<line x1="{margin_x}" y1="{height - margin_y}" '
        f'x2="{width - margin_x}" y2="{height - margin_y}" stroke="#ccc" />'
    )
    # Labels
    parts.append(
        f'<text x="{margin_x}" y="{height - 2}" font-size="10" fill="#999">0</text>'
    )
    parts.append(
        f'<text x="{width - margin_x}" y="{height - 2}" font-size="10" '
        f'fill="#999" text-anchor="end">{n}</text>'
    )

    # Verdict → y position
    verdict_y: dict[str, float] = {}
    for i, v in enumerate(_VERDICT_ORDER):
        verdict_y[v] = margin_y + (plot_h * i / max(len(_VERDICT_ORDER) - 1, 1))

    for i, c in enumerate(cases):
        x = margin_x + (plot_w * i / max(n - 1, 1))
        y = verdict_y.get(c.verdict, plot_h / 2 + margin_y)
        color = _VERDICT_COLORS.get(c.verdict, "#ccc")
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}" opacity="0.7">'
            f"<title>#{c.case_id} {c.verdict}</title></circle>"
        )

    parts.append("</svg>")
    return "\n".join(parts)


def _svg_bar_chart(cases: list[CaseResult], width: int = 600, height: int = 200) -> str:
    """Render profile/layer/strategy verdict distribution as horizontal stacked bars."""
    if not cases:
        return ""

    # Group by profile/layer/strategy
    groups: dict[str, dict[str, int]] = {}
    for c in cases:
        key = f"{c.profile}/{c.layer}/{c.strategy}"
        if key not in groups:
            groups[key] = {v: 0 for v in _VERDICT_ORDER}
        if c.verdict in groups[key]:
            groups[key][c.verdict] += 1

    margin_x, margin_y = 120, 20
    bar_h = 22
    gap = 6
    plot_w = width - margin_x - 20
    total_h = margin_y * 2 + len(groups) * (bar_h + gap)

    parts: list[str] = []
    parts.append(f'<svg width="{width}" height="{total_h}" viewBox="0 0 {width} {total_h}">')

    max_count = max((sum(v.values()) for v in groups.values()), default=1)

    for i, (label, verdicts) in enumerate(sorted(groups.items())):
        y = margin_y + i * (bar_h + gap)
        parts.append(
            f'<text x="{margin_x - 8}" y="{y + bar_h // 2 + 4}" '
            f'font-size="11" fill="#333" text-anchor="end">{_esc(label)}</text>'
        )
        x_offset = 0.0
        group_total = sum(verdicts.values())
        for v in _VERDICT_ORDER:
            count = verdicts.get(v, 0)
            if count == 0:
                continue
            w = plot_w * count / max(max_count, 1)
            color = _VERDICT_COLORS.get(v, "#ccc")
            parts.append(
                f'<rect x="{margin_x + x_offset:.1f}" y="{y}" '
                f'width="{w:.1f}" height="{bar_h}" fill="{color}" opacity="0.85">'
                f"<title>{v}: {count} ({_pct(count, group_total):.0f}%)</title></rect>"
            )
            x_offset += w

    parts.append("</svg>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Interesting case detail
# ---------------------------------------------------------------------------


def _render_interesting_case(case: CaseResult, interesting_dir: Path) -> str:
    """Render a single interesting case as an HTML details block."""
    case_dir = interesting_dir / f"case_{case.case_id:06d}"
    color = _VERDICT_COLORS.get(case.verdict, "#ccc")

    parts: list[str] = []
    parts.append(
        f'<div id="case-{case.case_id}" class="interesting-case" '
        f'style="border-left: 4px solid {color}; padding: 8px 12px; '
        f'margin: 8px 0; background: #fafafa;">'
    )
    parts.append(
        f"<strong>#{case.case_id}</strong> "
        f'<span style="color:{color};font-weight:bold;">{_esc(case.verdict)}</span> '
        f"{_esc(case.method)} {_esc(case.profile)} / "
        f"{_esc(case.layer)}/{_esc(case.strategy)} "
        f"seed={case.seed} ({case.elapsed_ms:.0f}ms)"
    )
    if case.response_code:
        parts.append(f" → {case.response_code}")
    parts.append(f"<br><small>{_esc(case.reason)}</small>")

    # Mutation ops
    if case.mutation_ops:
        parts.append("<br><small><b>Mutations:</b> " + _esc(", ".join(case.mutation_ops)) + "</small>")

    if case.details:
        parts.append(
            "<details><summary>Oracle Context</summary>"
            f'<pre style="background:#f5f5f5;padding:8px;overflow-x:auto;'
            f'font-size:11px;max-height:300px;">'
            f"{_esc(json.dumps(case.details, ensure_ascii=False, indent=2))}</pre></details>"
        )

    # Inline files from interesting/ dir
    for filename, label in [
        ("sent.sip", "Sent SIP"),
        ("sent.bin", "Sent (binary hex)"),
        ("response.sip", "Response SIP"),
        ("adb_log.txt", "ADB Log"),
        ("ios_log.txt", "iOS Log"),
        ("mutation_ops.txt", "Mutation Ops"),
    ]:
        fpath = case_dir / filename
        if fpath.is_file():
            if filename == "sent.bin":
                content = fpath.read_bytes().hex()
                content = "\n".join(
                    content[i : i + 80] for i in range(0, len(content), 80)
                )
            else:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            parts.append(
                f"<details><summary>{label}</summary>"
                f'<pre style="background:#f5f5f5;padding:8px;overflow-x:auto;'
                f'font-size:11px;max-height:400px;">{_esc(content)}</pre></details>'
            )

    # pcap download link
    pcap_path = case_dir / "capture.pcap"
    if pcap_path.is_file():
        rel = f"interesting/case_{case.case_id:06d}/capture.pcap"
        parts.append(f'<a href="{rel}" download>Download pcap</a>')

    # Reproduction command
    parts.append(
        f'<details><summary>Reproduction</summary>'
        f'<pre style="background:#f0f0f0;padding:6px;font-size:11px;">'
        f'{_esc(case.reproduction_cmd)}</pre></details>'
    )

    parts.append("</div>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Full HTML
# ---------------------------------------------------------------------------


class HtmlReportGenerator:
    """Generates a standalone HTML report from campaign JSONL."""

    def __init__(self, jsonl_path: Path) -> None:
        self._jsonl_path = jsonl_path

    def generate(self, output_path: Path | None = None) -> Path:
        """Generate HTML report. Returns the output path."""
        from volte_mutation_fuzzer.campaign.core import ResultStore

        store = ResultStore(self._jsonl_path)
        header, cases = store.read_all()

        if output_path is None:
            output_path = self._jsonl_path.parent / "report.html"

        interesting_dir = self._jsonl_path.parent / "interesting"

        html_content = self._build_html(header, cases, interesting_dir)
        output_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report generated: %s", output_path)
        return output_path

    def _build_html(
        self,
        header: CampaignResult,
        cases: list[CaseResult],
        interesting_dir: Path,
    ) -> str:
        summary = header.summary
        parts: list[str] = []

        # Head
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="ko"><head><meta charset="utf-8">')
        parts.append(f"<title>Campaign Report: {_esc(header.campaign_id)}</title>")
        parts.append(self._css())
        parts.append("</head><body>")

        # Header
        duration = ""
        if header.started_at and header.completed_at:
            duration = f" | {_esc(header.started_at[:16])} ~ {_esc(header.completed_at[:16])}"
        parts.append(
            f'<h1>Campaign Report: {_esc(header.campaign_id)}'
            f'<span class="status {header.status}">{header.status}</span></h1>'
        )
        parts.append(f"<p>Total: {summary.total} cases{duration}</p>")

        # Section 1: Summary
        parts.append('<h2>1. Summary</h2>')
        parts.append('<div class="summary-row">')
        parts.append(f'<div class="chart-box">{_svg_donut(summary)}</div>')
        parts.append('<div class="legend">')
        for v in _VERDICT_ORDER:
            count = getattr(summary, v, 0)
            color = _VERDICT_COLORS[v]
            pct = _pct(count, summary.total)
            parts.append(
                f'<div><span class="dot" style="background:{color}"></span>'
                f"{v}: {count} ({pct:.0f}%)</div>"
            )
        parts.append("</div></div>")

        # Section 2: Strategy/Layer bar chart
        parts.append('<h2>2. Profile / Layer / Strategy Distribution</h2>')
        parts.append(_svg_bar_chart(cases))

        # Section 3: Timeline
        parts.append('<h2>3. Verdict Timeline</h2>')
        parts.append(_svg_timeline(cases))

        # Section 4: Interesting cases
        interesting_cases = [c for c in cases if c.verdict in _INTERESTING_VERDICTS]
        parts.append(f'<h2>4. Interesting Cases ({len(interesting_cases)})</h2>')
        if interesting_cases:
            for c in interesting_cases:
                parts.append(_render_interesting_case(c, interesting_dir))
        else:
            parts.append("<p>No crash/suspicious/stack_failure cases found.</p>")

        # Section 5: All cases table
        parts.append(f'<h2>5. All Cases ({len(cases)})</h2>')
        parts.append(self._cases_table(cases))

        # Section 6: Config
        parts.append('<h2>6. Config</h2>')
        parts.append("<details><summary>CampaignConfig</summary>")
        config_json = json.dumps(
            header.config.model_dump(mode="json"), ensure_ascii=False, indent=2
        )
        parts.append(f'<pre style="font-size:11px;">{_esc(config_json)}</pre>')
        parts.append("</details>")

        # JS for filtering
        parts.append(self._filter_js())

        parts.append("</body></html>")
        return "\n".join(parts)

    def _cases_table(self, cases: list[CaseResult]) -> str:
        parts: list[str] = []

        # Filter checkboxes
        parts.append('<div class="filters">')
        parts.append("<strong>Filter:</strong> ")
        for v in _VERDICT_ORDER:
            color = _VERDICT_COLORS[v]
            parts.append(
                f'<label><input type="checkbox" class="verdict-filter" '
                f'value="{v}" checked '
                f'onchange="filterTable()">'
                f'<span class="dot" style="background:{color}"></span>{v}</label> '
            )
        parts.append("</div>")

        parts.append('<table id="cases-table"><thead><tr>')
        for col in (
            "ID",
            "Method",
            "Profile",
            "Layer",
            "Strategy",
            "Seed",
            "Verdict",
            "Code",
            "ms",
            "Wall",
            "Context",
        ):
            parts.append(f"<th>{col}</th>")
        parts.append("</tr></thead><tbody>")

        for c in cases:
            color = _VERDICT_COLORS.get(c.verdict, "#ccc")
            row_class = f"verdict-{c.verdict}"
            code_str = str(c.response_code) if c.response_code else ""
            is_interesting = c.verdict in _INTERESTING_VERDICTS
            id_cell = (
                f'<a href="#case-{c.case_id}">{c.case_id}</a>'
                if is_interesting
                else str(c.case_id)
            )
            context_text = "<br>".join(_esc(line) for line in _context_lines(c))
            wall_ms_str = "" if c.case_wall_ms is None else f"{c.case_wall_ms:.0f}"
            parts.append(
                f'<tr class="{row_class}" style="border-left: 3px solid {color};">'
                f"<td>{id_cell}</td>"
                f"<td>{_esc(c.method)}</td>"
                f"<td>{_esc(c.profile)}</td>"
                f"<td>{_esc(c.layer)}</td>"
                f"<td>{_esc(c.strategy)}</td>"
                f"<td>{c.seed}</td>"
                f'<td style="color:{color};font-weight:bold;">{_esc(c.verdict)}</td>'
                f"<td>{code_str}</td>"
                f"<td>{c.elapsed_ms:.0f}</td>"
                f"<td>{wall_ms_str}</td>"
                f"<td>{context_text}</td>"
                f"</tr>"
            )

        parts.append("</tbody></table>")
        return "\n".join(parts)

    def _css(self) -> str:
        return """<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       max-width: 1000px; margin: 0 auto; padding: 20px; color: #333; }
h1 { font-size: 20px; }
h2 { font-size: 16px; margin-top: 28px; border-bottom: 1px solid #eee; padding-bottom: 4px; }
.status { font-size: 12px; padding: 2px 8px; border-radius: 4px; margin-left: 8px;
           color: white; vertical-align: middle; }
.status.completed { background: #4caf50; }
.status.aborted { background: #ff9800; }
.status.running { background: #2196f3; }
.summary-row { display: flex; align-items: center; gap: 24px; }
.chart-box { flex-shrink: 0; }
.legend { font-size: 13px; }
.legend div { margin: 3px 0; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
        margin-right: 6px; vertical-align: middle; }
table { border-collapse: collapse; width: 100%; font-size: 12px; margin-top: 8px; }
th { background: #f5f5f5; text-align: left; padding: 6px 8px; font-weight: 600; }
td { padding: 4px 8px; border-bottom: 1px solid #eee; }
tr:hover { background: #f9f9f9; }
.filters { margin: 8px 0; font-size: 12px; }
.filters label { margin-right: 10px; cursor: pointer; }
details { margin: 4px 0; }
summary { cursor: pointer; font-size: 12px; color: #555; }
a { color: #1976d2; text-decoration: none; }
a:hover { text-decoration: underline; }
</style>"""

    def _filter_js(self) -> str:
        return """<script>
function filterTable() {
  const checks = document.querySelectorAll('.verdict-filter');
  const visible = new Set();
  checks.forEach(cb => { if (cb.checked) visible.add(cb.value); });
  const rows = document.querySelectorAll('#cases-table tbody tr');
  rows.forEach(row => {
    const cls = Array.from(row.classList).find(c => c.startsWith('verdict-'));
    const verdict = cls ? cls.replace('verdict-', '') : '';
    row.style.display = visible.has(verdict) ? '' : 'none';
  });
}
</script>"""
