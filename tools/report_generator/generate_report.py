#!/usr/bin/env python3
"""Generate a print-ready AURA app risk report from a JSON export."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any


DECISION_ORDER = {"RED": 0, "YELLOW": 1, "BLUE": 2, "GRAY": 3, "GREEN": 4}
POSTURE_ORDER = {
    "WEAK_DEFENSIVE_SURFACE": 0,
    "REVIEW_RECOMMENDED": 1,
    "NO_OBSERVED_WEAKNESS": 2,
}


def load_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return json.loads(path.read_text())


def decision_counts(export: dict[str, Any]) -> Counter[str]:
    return Counter(
        assessment.get("decision", {}).get("color", "UNKNOWN")
        for assessment in export.get("assessments", [])
    )


def postures_by_package(export: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        posture.get("packageName", ""): posture
        for posture in export.get("defensivePostures", [])
    }


def findings_by_package(export: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in export.get("defensiveSurfaceFindings", []):
        output[finding.get("packageName", "")].append(finding)
    return output


def sorted_assessments(export: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        export.get("assessments", []),
        key=lambda assessment: (
            DECISION_ORDER.get(assessment.get("decision", {}).get("color", "GREEN"), 9),
            assessment.get("snapshot", {}).get("packageName", ""),
        ),
    )


def top_posture_items(export: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        export.get("defensivePostures", []),
        key=lambda posture: (
            POSTURE_ORDER.get(posture.get("postureClass", "NO_OBSERVED_WEAKNESS"), 9),
            -int(posture.get("findingCount", 0)),
            posture.get("packageName", ""),
        ),
    )


def iso_time(millis: int | float | None) -> str:
    if not millis:
        return "unknown"
    return datetime.fromtimestamp(float(millis) / 1000, timezone.utc).isoformat()


def score(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def md_escape(value: Any) -> str:
    text = str(value or "")
    return text.replace("|", "\\|").replace("\n", " ").strip()


def title_for_app(assessment: dict[str, Any]) -> str:
    snapshot = assessment.get("snapshot", {})
    label = snapshot.get("appLabel") or snapshot.get("packageName", "")
    return f"{label} ({snapshot.get('packageName', '')})"


def risk_vector_text(assessment: dict[str, Any]) -> str:
    risk = assessment.get("riskVector", {})
    return (
        f"H={score(risk.get('harm'))} "
        f"L={score(risk.get('legitimacy'))} "
        f"E={score(risk.get('abuseEvidence'))} "
        f"P={score(risk.get('provenanceConfidence'))} "
        f"A={score(risk.get('actionability'))} "
        f"U={score(risk.get('uncertainty'))}"
    )


def matched_rules(assessment: dict[str, Any]) -> list[str]:
    return [
        rule.get("ruleId", "")
        for rule in assessment.get("decisionTrace", {}).get("evaluatedRules", [])
        if rule.get("matched") is True and rule.get("ruleId")
    ]


def invariant_failures(assessment: dict[str, Any]) -> list[str]:
    return [
        item.get("invariantId", "")
        for item in assessment.get("decisionTrace", {}).get("invariantChecks", [])
        if item.get("passed") is False
    ]


def recommended_actions(assessment: dict[str, Any]) -> list[str]:
    return [
        f"{action.get('title', action.get('actionId', 'action'))}: {action.get('description', '')}"
        for action in assessment.get("decision", {}).get("recommendedActions", [])
    ]


def evidence_lines(assessment: dict[str, Any], limit: int = 4) -> list[str]:
    lines = []
    for evidence in assessment.get("evidence", [])[:limit]:
        lines.append(
            f"{evidence.get('source')} / {evidence.get('observabilityState')} / "
            f"conf={score(evidence.get('confidence'))}: {evidence.get('humanExplanation', '')}"
        )
    return lines


def baseline_section(evaluation: dict[str, Any] | None) -> list[str]:
    if not evaluation:
        return [
            "## Baseline Comparison",
            "",
            "No evaluator output was supplied for this report.",
            "",
        ]
    metrics = evaluation.get("metrics", {})
    model_metrics = evaluation.get("modelMetrics", {})
    permission = model_metrics.get("permission_only", {})
    full = model_metrics.get("full_aura", {})
    lines = [
        "## Baseline Comparison",
        "",
        "| Metric | Permission-only | Full AURA |",
        "| --- | ---: | ---: |",
        f"| Critical alert rate | {score(permission.get('critical_alert_rate'))} | {score(full.get('critical_alert_rate'))} |",
        f"| Non-actionable critical alert rate | {score(permission.get('non_actionable_critical_alert_rate'))} | {score(full.get('non_actionable_critical_alert_rate'))} |",
        f"| User-actionable precision | {score(permission.get('user_actionable_precision'))} | {score(full.get('user_actionable_precision'))} |",
        f"| Controlled-abuse recall | {score(permission.get('controlled_abuse_recall'))} | {score(full.get('controlled_abuse_recall'))} |",
        f"| BLUE platform audit separation | {score(permission.get('platform_audit_separation'))} | {score(full.get('platform_audit_separation'))} |",
        "",
        f"Decision trace completeness: `{score(metrics.get('decision_trace_completeness'))}`",
        "",
    ]
    comparisons = evaluation.get("comparisons", {})
    if comparisons:
        lines += [
            "Key comparison deltas:",
            "",
            f"- Non-actionable critical alert reduction vs permission-only: `{score(comparisons.get('aura_non_actionable_critical_alert_rate_reduction_vs_permission_only'))}`",
            f"- User-actionable precision delta vs permission-only: `{score(comparisons.get('aura_user_actionable_precision_delta_vs_permission_only'))}`",
            f"- Controlled-abuse recall delta vs permission-only: `{score(comparisons.get('aura_controlled_abuse_recall_delta_vs_permission_only'))}`",
            "",
        ]
    return lines


def app_detail_section(
    assessment: dict[str, Any],
    posture: dict[str, Any] | None,
    findings: list[dict[str, Any]],
) -> list[str]:
    snapshot = assessment.get("snapshot", {})
    decision = assessment.get("decision", {})
    role = assessment.get("role", {})
    provenance = assessment.get("provenance", {})
    story = assessment.get("userRiskStory", {})
    trace = assessment.get("decisionTrace", {})
    lines = [
        f"### {md_escape(title_for_app(assessment))}",
        "",
        f"- Threat decision: `{decision.get('color')}` / {decision.get('title', '')}",
        f"- Defensive posture: `{(posture or {}).get('postureClass', 'NO_OBSERVED_WEAKNESS')}` with `{(posture or {}).get('findingCount', 0)}` finding(s)",
        f"- Role: `{role.get('predicted')}` confidence `{score(role.get('confidence'))}`",
        f"- Provenance: `{provenance.get('provenanceClass')}` confidence `{score(provenance.get('confidence'))}`",
        f"- Actionability: `{decision.get('actionabilityClass')}`",
        f"- Risk vector: `{risk_vector_text(assessment)}`",
        f"- Source partition: `{snapshot.get('rawFeatures', {}).get('sourcePartition', 'unknown')}`",
        "",
        f"Risk story: {story.get('primaryReason', decision.get('explanation', ''))}",
        "",
    ]
    observed = story.get("whatWasObserved", [])
    if observed:
        lines += ["Observed:", ""]
        lines += [f"- {item}" for item in observed[:6]]
        lines += [""]
    actions = recommended_actions(assessment)
    if actions:
        lines += ["Recommended actions:", ""]
        lines += [f"- {action}" for action in actions[:5]]
        lines += [""]
    rules = matched_rules(assessment)
    lines += [
        "Decision trace:",
        "",
        f"- Policy version: `{trace.get('policyVersion', 'unknown')}`",
        f"- Matched rules: `{', '.join(rules) if rules else 'none'}`",
        f"- Invariant failures: `{', '.join(invariant_failures(assessment)) or 'none'}`",
        "",
    ]
    counterfactuals = trace.get("counterfactuals", [])
    if counterfactuals:
        lines += ["Counterfactuals:", ""]
        for item in counterfactuals[:3]:
            changes = "; ".join(item.get("requiredChanges", []))
            lines.append(f"- To reach `{item.get('targetDecision')}`: {changes}")
        lines += [""]
    evidence = evidence_lines(assessment)
    if evidence:
        lines += ["Top evidence:", ""]
        lines += [f"- {line}" for line in evidence]
        lines += [""]
    if findings:
        lines += ["Defensive surface findings:", ""]
        for finding in findings[:6]:
            lines.append(
                f"- `{finding.get('findingType')}` severity `{finding.get('severity')}` "
                f"confidence `{score(finding.get('confidence'))}`: {finding.get('humanExplanation', '')}"
            )
        lines += [""]
    return lines


def render_markdown(
    export: dict[str, Any],
    evaluation: dict[str, Any] | None = None,
    *,
    top_apps: int = 12,
) -> str:
    counts = decision_counts(export)
    postures = postures_by_package(export)
    findings = findings_by_package(export)
    assessments = sorted_assessments(export)
    posture_counts = Counter(
        posture.get("postureClass", "NO_OBSERVED_WEAKNESS")
        for posture in export.get("defensivePostures", [])
    )
    red = counts.get("RED", 0)
    yellow = counts.get("YELLOW", 0)
    blue = counts.get("BLUE", 0)
    gray = counts.get("GRAY", 0)
    green = counts.get("GREEN", 0)
    lines = [
        "# AURA Android App Risk Report",
        "",
        f"Generated from scan `{export.get('scanId', 'unknown')}`.",
        "",
        "## Executive Summary",
        "",
        f"- Generated at: `{iso_time(export.get('generatedAt'))}`",
        f"- Flavor: `{export.get('flavor', 'unknown')}`",
        f"- Applications assessed: `{len(export.get('assessments', []))}`",
        f"- Threat decisions: RED `{red}`, YELLOW `{yellow}`, BLUE `{blue}`, GRAY `{gray}`, GREEN `{green}`",
        f"- Defensive posture: weak `{posture_counts.get('WEAK_DEFENSIVE_SURFACE', 0)}`, review `{posture_counts.get('REVIEW_RECOMMENDED', 0)}`, no observed weakness `{posture_counts.get('NO_OBSERVED_WEAKNESS', 0)}`",
        f"- Temporal episodes: `{len(export.get('temporalEpisodes', []))}`",
        f"- Defensive findings: `{len(export.get('defensiveSurfaceFindings', []))}`",
        "",
        "AURA separates threat decisions from defensive posture. A `GREEN` threat decision means the current scan did not find concrete abuse evidence; it does not mean the app has perfect defensive design.",
        "",
        "## Methodology",
        "",
        "AURA is a no-root Android risk reasoning engine. It evaluates app capabilities in relation to inferred role, provenance, abuse evidence, user actionability, and observability limits. It does not replace Play Protect, MDM/MTD, or a manual mobile application pentest.",
        "",
        "Privacy defaults: no TLS interception, no keylogging, no screen scraping, no notification-content reading, and no external telemetry in the MVP.",
        "",
        "## Threat Decision Overview",
        "",
        "| Decision | Meaning | Count |",
        "| --- | --- | ---: |",
        f"| RED | User-actionable threat | {red} |",
        f"| YELLOW | Review recommended | {yellow} |",
        f"| BLUE | Expert/platform audit finding, not primary panic | {blue} |",
        f"| GRAY | Insufficient evidence / abstention | {gray} |",
        f"| GREEN | No user action required from current threat evidence | {green} |",
        "",
    ]
    lines += baseline_section(evaluation)
    lines += [
        "## Priority Items",
        "",
    ]
    priority = [
        item
        for item in assessments
        if item.get("decision", {}).get("color") in {"RED", "YELLOW", "BLUE", "GRAY"}
    ][:top_apps]
    if not priority:
        lines += ["No non-GREEN priority items were present in this export.", ""]
    else:
        for assessment in priority:
            package_name = assessment.get("snapshot", {}).get("packageName", "")
            lines += app_detail_section(assessment, postures.get(package_name), findings.get(package_name, []))
    weak_postures = [
        posture
        for posture in top_posture_items(export)
        if posture.get("postureClass") != "NO_OBSERVED_WEAKNESS"
    ][:top_apps]
    lines += [
        "## Defensive Posture Highlights",
        "",
    ]
    if not weak_postures:
        lines += ["No defensive posture findings were exported.", ""]
    else:
        lines += ["| Package | Posture | Findings | Highest severity |", "| --- | --- | ---: | --- |"]
        for posture in weak_postures:
            lines.append(
                f"| `{md_escape(posture.get('packageName'))}` | `{posture.get('postureClass')}` | "
                f"{posture.get('findingCount', 0)} | `{posture.get('highestSeverity') or 'n/a'}` |"
            )
        lines += [""]
    episodes = export.get("temporalEpisodes", [])
    lines += ["## Temporal Episodes", ""]
    if not episodes:
        lines += ["No temporal episodes were exported.", ""]
    else:
        lines += ["| Package | Type | Explanation |", "| --- | --- | --- |"]
        for episode in episodes[:top_apps]:
            lines.append(
                f"| `{md_escape(episode.get('packageName'))}` | `{episode.get('type')}` | {md_escape(episode.get('explanation'))} |"
            )
        lines += [""]
    lines += [
        "## Observability Limits",
        "",
        "- AURA is a no-root agent and cannot observe kernel, baseband, TEE, bootloader, or hidden OEM framework compromise.",
        "- Declared-only capabilities are not treated the same as active risky access.",
        "- Unknown evidence increases uncertainty; it is not treated as malicious by default.",
        "- BLUE findings are expert/platform audit items and must not appear in the primary panic queue.",
        "- Defensive posture findings are app-hardening signals, not malware verdicts.",
        "",
        "## Appendix",
        "",
        f"- Export schema version: `{export.get('schemaVersion')}`",
        f"- Scan history retained scans: `{(export.get('scanHistory') or {}).get('retainedScanCount', 'n/a')}`",
        f"- Scan history retained packages: `{(export.get('scanHistory') or {}).get('retainedPackageCount', 'n/a')}`",
        "",
    ]
    return "\n".join(lines)


def markdown_to_html(markdown_text: str) -> str:
    body = []
    in_table = False
    in_list = False
    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if not line:
            if in_list:
                body.append("</ul>")
                in_list = False
            if in_table:
                body.append("</tbody></table>")
                in_table = False
            continue
        if line.startswith("# "):
            body.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{escape(line[4:])}</h3>")
        elif line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{inline_html(line[2:])}</li>")
        elif line.startswith("| ") and line.endswith(" |"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if all(set(cell) <= {"-", ":", " "} for cell in cells):
                continue
            if not in_table:
                body.append("<table><tbody>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            body.append("<tr>" + "".join(f"<{tag}>{inline_html(cell)}</{tag}>" for cell in cells) + "</tr>")
        else:
            if in_list:
                body.append("</ul>")
                in_list = False
            if in_table:
                body.append("</tbody></table>")
                in_table = False
            body.append(f"<p>{inline_html(line)}</p>")
    if in_list:
        body.append("</ul>")
    if in_table:
        body.append("</tbody></table>")
    return "\n".join(body)


def inline_html(text: str) -> str:
    escaped = escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def render_html(markdown_text: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AURA Android App Risk Report</title>
  <style>
    :root {{
      --ink: #14211f;
      --muted: #5c6865;
      --line: #d9e1dd;
      --surface: #f8faf7;
      --accent: #145c58;
      --danger: #b3261e;
    }}
    body {{
      margin: 0;
      color: var(--ink);
      background: white;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 980px;
      margin: 0 auto;
      padding: 42px 28px 80px;
    }}
    h1 {{
      font-size: 34px;
      margin: 0 0 12px;
      color: var(--accent);
    }}
    h2 {{
      margin-top: 34px;
      padding-top: 18px;
      border-top: 1px solid var(--line);
      font-size: 23px;
    }}
    h3 {{
      margin-top: 26px;
      font-size: 18px;
    }}
    p, li, td, th {{
      font-size: 14px;
    }}
    p {{
      margin: 8px 0;
    }}
    code {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 1px 5px;
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 18px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 8px 7px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 700;
      background: var(--surface);
    }}
    ul {{
      margin-top: 6px;
    }}
    @media print {{
      main {{
        max-width: none;
        padding: 18mm;
      }}
      h2 {{
        break-after: avoid;
      }}
      h3, table {{
        break-inside: avoid;
      }}
    }}
  </style>
</head>
<body>
<main>
{markdown_to_html(markdown_text)}
</main>
</body>
</html>
"""


def write_report(
    export: dict[str, Any],
    evaluation: dict[str, Any] | None,
    out_dir: Path,
    basename: str,
    top_apps: int,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(export, evaluation, top_apps=top_apps)
    markdown_path = out_dir / f"{basename}.md"
    html_path = out_dir / f"{basename}.html"
    markdown_path.write_text(markdown + "\n")
    html_path.write_text(render_html(markdown))
    return markdown_path, html_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="AURA scan export JSON")
    parser.add_argument("--evaluation", type=Path, help="Optional evaluator JSON output")
    parser.add_argument("--out-dir", type=Path, default=Path("artifacts/reports"))
    parser.add_argument("--basename", default="aura-app-risk-report")
    parser.add_argument("--top-apps", type=int, default=12)
    args = parser.parse_args()

    export = load_json(args.export)
    if export is None:
        raise ValueError(f"Could not load export {args.export}")
    evaluation = load_json(args.evaluation)
    markdown_path, html_path = write_report(
        export=export,
        evaluation=evaluation,
        out_dir=args.out_dir,
        basename=args.basename,
        top_apps=args.top_apps,
    )
    print(f"Wrote Markdown report to {markdown_path}")
    print(f"Wrote HTML report to {html_path}")
    print("Open the HTML report in a browser and print/save as PDF when a PDF artifact is needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
