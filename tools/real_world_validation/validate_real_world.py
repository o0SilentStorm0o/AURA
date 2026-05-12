#!/usr/bin/env python3
"""Generate and score real-world AURA app-owner validation reports.

This harness is intentionally product-facing: it does not ask whether AURA can
find an artificial leaky fixture. It asks whether AURA can turn public app
signals into a short, useful, low-noise release-risk conversation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "app_owner_audit"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "report_generator"))

from audit_engine import build_audit  # noqa: E402
from generate_report import mark_target_only_privacy, scope_export_to_package, write_report  # noqa: E402


DEFAULT_TARGETS = Path(__file__).with_name("validation_targets.json")
SENSITIVE_COMPONENT_TOKENS = (
    "auth",
    "payment",
    "checkout",
    "redirect",
    "callback",
    "token",
    "webview",
    "deeplink",
    "link",
)
SDK_COMPONENT_TOKENS = (
    "androidx.",
    "com.facebook.",
    "com.google.",
    "com.huawei.",
    "com.stripe.",
    "com.sendbird.",
    "com.ravelin.",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def score(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def finding_raw(finding: dict[str, Any]) -> str:
    return str((finding.get("evidence") or {}).get("rawValue") or "")


def has_token(value: str, tokens: tuple[str, ...]) -> bool:
    lower = value.lower()
    return any(token in lower for token in tokens)


def classify_finding(finding: dict[str, Any]) -> str:
    finding_type = str(finding.get("type") or "")
    status = str(finding.get("status") or "")
    raw = finding_raw(finding)
    component_class = str((finding.get("componentClassification") or {}).get("componentClass") or "")
    if status in {"ACCEPTED_RISK", "NOT_APPLICABLE"}:
        return "accepted_or_not_applicable"
    if status == "INFO":
        return "trivial_context"
    if finding_type in {
        "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE",
        "CLEARTEXT_TRAFFIC_ALLOWED",
        "BACKUP_MAY_INCLUDE_SENSITIVE_DATA",
        "WEBVIEW_RISKY_CONFIGURATION",
        "SECRETS_OR_ENDPOINTS_IN_APK",
        "DEEPLINK_ACCEPTS_UNTRUSTED_INPUT",
    }:
        return "valuable"
    if finding_type == "EXPORTED_COMPONENT_WITHOUT_GUARD":
        if component_class in {"PAYMENT_REDIRECT", "AUTH_CALLBACK", "DEEPLINK_ROUTER", "WEBVIEW_ENTRYPOINT", "CUSTOMER_DATA_FLOW"}:
            return "valuable"
        if component_class in {"SDK_CALLBACK", "PUSH_SERVICE", "ANALYTICS_RECEIVER", "PREVIEW_OR_TOOLING"}:
            return "needs_context"
        if has_token(raw, SENSITIVE_COMPONENT_TOKENS):
            return "valuable"
        if has_token(raw, SDK_COMPONENT_TOKENS):
            return "needs_context"
        return "manual_review"
    if finding_type.startswith("SENSITIVE_") or finding_type.startswith("MISSING_TAPJACKING"):
        return "manual_review"
    if finding_type == "UNCLASSIFIED_RELEASE_REVIEW_FINDING":
        return "noise_risk"
    return "manual_review"


def classify_report(audit: dict[str, Any]) -> dict[str, Any]:
    findings = audit.get("findings", [])
    groups = audit.get("findingGroups", [])
    classes = Counter(classify_finding(finding) for finding in findings)
    customer_visible = [
        finding for finding in findings
        if finding.get("status") in {"BLOCKER", "SHOULD_FIX", "REVIEW"}
    ]
    sdk_like_components = [
        finding for finding in findings
        if finding.get("type") == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        and has_token(finding_raw(finding), SDK_COMPONENT_TOKENS)
    ]
    sensitive_components = [
        finding for finding in findings
        if finding.get("type") == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        and (
            str((finding.get("componentClassification") or {}).get("componentClass") or "")
            in {"PAYMENT_REDIRECT", "AUTH_CALLBACK", "DEEPLINK_ROUTER", "WEBVIEW_ENTRYPOINT", "CUSTOMER_DATA_FLOW"}
            or has_token(finding_raw(finding), SENSITIVE_COMPONENT_TOKENS)
        )
    ]
    customer_visible_groups = [
        group for group in groups
        if group.get("status") in {"BLOCKER", "SHOULD_FIX", "REVIEW"}
    ]
    if not groups:
        customer_visible_groups = customer_visible
    noise_flags: list[str] = []
    if len(customer_visible_groups) > 6:
        noise_flags.append("too_many_customer_visible_review_areas")
    if len(sdk_like_components) >= 3:
        noise_flags.append("sdk_component_context_needed")
    if audit.get("policyQualityMetrics", {}).get("manualReviewRate", 0.0) > 0.75 and customer_visible:
        noise_flags.append("manual_review_heavy")
    if not customer_visible:
        value = "negative_control"
    elif classes.get("valuable", 0) >= 2 and len(customer_visible_groups) <= 6:
        value = "strong"
    elif classes.get("valuable", 0) >= 1:
        value = "promising_but_needs_triage"
    else:
        value = "weak_or_context_dependent"
    teaser_candidate = value in {"strong", "promising_but_needs_triage"} and "too_many_customer_visible_review_areas" not in noise_flags
    return {
        "findingClassCounts": dict(classes),
        "customerVisibleFindingCount": len(customer_visible),
        "customerVisibleReviewAreaCount": len(customer_visible_groups),
        "sdkLikeComponentCount": len(sdk_like_components),
        "sensitiveComponentCount": len(sensitive_components),
        "noiseFlags": noise_flags,
        "commercialValue": value,
        "goodTeaserCandidate": teaser_candidate,
    }


def validation_note(audit: dict[str, Any], classification: dict[str, Any]) -> str:
    counts = audit.get("priorityCounts", {})
    if classification["commercialValue"] == "negative_control":
        return "Useful negative control: AURA avoids panic, but outreach wow is low unless framed as no-noise evidence."
    if "too_many_customer_visible_review_areas" in classification["noiseFlags"]:
        return "Useful stress case, but report still needs human triage before customer delivery."
    if classification["findingClassCounts"].get("valuable", 0):
        return "Promising: at least one finding maps to a contextually meaningful release-risk conversation."
    if counts.get("P3", 0):
        return "Mostly review-level. Needs customer profile/offline APK context before this becomes commercially compelling."
    return "Low current signal. Keep as corpus coverage, not a primary sales demo."


def validate_target(
    export: dict[str, Any],
    target: dict[str, Any],
    out_dir: Path,
) -> dict[str, Any]:
    profile = target.get("profile") or {}
    scoped = mark_target_only_privacy(scope_export_to_package(export, target["packageName"]))
    audit = build_audit(scoped, app_profile=profile)
    report_dir = out_dir / "reports"
    basename = f"aura-realworld-{target['id']}"
    markdown_path, html_path = write_report(
        export=scoped,
        evaluation=None,
        out_dir=report_dir,
        basename=basename,
        top_apps=12,
        report_type="app_owner",
        app_profile=profile,
    )
    classification = classify_report(audit)
    return {
        "targetId": target["id"],
        "clientName": target.get("clientName"),
        "appName": target.get("appName"),
        "packageName": target["packageName"],
        "profile": profile,
        "validationRole": target.get("validationRole"),
        "releaseStatus": audit.get("releaseStatus"),
        "priorityCounts": audit.get("priorityCounts"),
        "statusCounts": audit.get("statusCounts"),
        "policyQualityMetrics": audit.get("policyQualityMetrics"),
        "findingGroups": audit.get("findingGroups", []),
        "classification": classification,
        "validationNote": validation_note(audit, classification),
        "reportMarkdown": str(markdown_path),
        "reportHtml": str(html_path),
        "topFindings": [
            {
                "id": finding.get("id"),
                "status": finding.get("status"),
                "priority": finding.get("priority"),
                "type": finding.get("type"),
                "title": finding.get("title"),
                "rawValue": finding_raw(finding),
                "classification": classify_finding(finding),
            }
            for finding in audit.get("findings", [])[:12]
        ],
        "topReviewAreas": [
            {
                "id": group.get("id"),
                "status": group.get("status"),
                "priority": group.get("priority"),
                "title": group.get("title"),
                "findingCount": group.get("findingCount"),
                "componentCount": group.get("componentCount"),
                "evidenceStrength": group.get("evidenceStrength"),
            }
            for group in audit.get("findingGroups", [])[:8]
        ],
    }


def markdown_summary(results: list[dict[str, Any]], source_export: Path) -> str:
    lines = [
        "# AURA Real-World Validation Summary",
        "",
        f"Source export: `{source_export}`",
        "",
        "This is an internal product-testing artifact. It scores whether AURA's app-owner reports look commercially useful on real public apps, not just on deliberately broken fixtures.",
        "",
        "## Target Summary",
        "",
        "| Target | Profile | Release | P1 | P2 | P3 | Areas | Value | Noise flags | Report |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
    ]
    for result in results:
        profile = result.get("profile") or {}
        counts = result.get("priorityCounts") or {}
        classification = result.get("classification") or {}
        lines.append(
            f"| {result.get('clientName')} / {result.get('appName')} | "
            f"`{profile.get('appCategory')}/{profile.get('dataSensitivity')}` | "
            f"`{(result.get('releaseStatus') or {}).get('status')}` | "
            f"{counts.get('P1', 0)} | {counts.get('P2', 0)} | {counts.get('P3', 0)} | "
            f"{classification.get('customerVisibleReviewAreaCount', 0)} | "
            f"`{classification.get('commercialValue')}` | "
            f"`{', '.join(classification.get('noiseFlags', [])) or 'none'}` | "
            f"[html]({result.get('reportHtml')}) |"
        )
    lines += [
        "",
        "## Findings From Testing AURA Itself",
        "",
    ]
    for result in results:
        metrics = result.get("policyQualityMetrics") or {}
        classification = result.get("classification") or {}
        lines += [
            f"### {result.get('clientName')} / {result.get('appName')}",
            "",
            f"- Package: `{result.get('packageName')}`",
            f"- Validation role: `{result.get('validationRole')}`",
            f"- Commercial value: `{classification.get('commercialValue')}`",
            f"- Good teaser candidate: `{classification.get('goodTeaserCandidate')}`",
            f"- Customer-visible findings: `{classification.get('customerVisibleFindingCount')}`",
            f"- Customer-visible review areas: `{classification.get('customerVisibleReviewAreaCount')}`",
            f"- Valuable findings: `{classification.get('findingClassCounts', {}).get('valuable', 0)}`",
            f"- SDK-like component context needed: `{classification.get('sdkLikeComponentCount')}`",
            f"- Manual review rate: `{score(metrics.get('manualReviewRate'))}`",
            f"- Actionable rate: `{score(metrics.get('actionableRate'))}`",
            f"- Note: {result.get('validationNote')}",
            "",
        ]
        if result.get("topFindings"):
            if result.get("topReviewAreas"):
                lines += ["Top review areas:", ""]
                for group in result["topReviewAreas"][:5]:
                    strength = group.get("evidenceStrength") or {}
                    lines.append(
                        f"- `{group['priority']}` `{group['status']}`: {group['title']} "
                        f"({group.get('findingCount')} findings, evidence: {strength.get('level', 'unknown')})"
                    )
                lines.append("")
            lines += ["Top findings:", ""]
            for finding in result["topFindings"][:6]:
                lines.append(
                    f"- `{finding['priority']}` `{finding['status']}` `{finding['type']}` "
                    f"({finding['classification']}): {finding['title']}"
                )
            lines.append("")
        else:
            lines += ["Top findings: none.", ""]
    lines += [
        "## Product Interpretation",
        "",
        "- Negative-control apps are useful: they prove AURA can avoid panic, but they are weak sales demos by themselves.",
        "- Reports with many SDK/exported-component items should be judged by review areas first and raw components second; otherwise AURA risks looking like another lint dump.",
        "- Strong sales candidates should produce a small number of context-rich `SHOULD_FIX`/`REVIEW` items such as auth/payment/deep-link/WebView surfaces, not just generic permission counts.",
        "- Offline APK analysis remains a major next lever because on-device metadata cannot distinguish benign SDK callback surfaces from real app-owned logic.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "artifacts" / "real_world_validation")
    args = parser.parse_args()

    export = load_json(args.export)
    targets = load_json(args.targets).get("targets", [])
    args.out_dir.mkdir(parents=True, exist_ok=True)
    results = [validate_target(export, target, args.out_dir) for target in targets]
    results_path = args.out_dir / "validation-results.json"
    summary_path = args.out_dir / "validation-summary.md"
    results_path.write_text(json.dumps({"schemaVersion": 1, "results": results}, indent=2, sort_keys=True) + "\n")
    summary_path.write_text(markdown_summary(results, args.export) + "\n")
    print(f"Wrote validation JSON to {results_path}")
    print(f"Wrote validation summary to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
