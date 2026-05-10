package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ActionabilityClass
import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DefensiveFindingSeverity
import cz.davidstrnadel.aura.core.DefensiveFindingType
import cz.davidstrnadel.aura.core.DefensiveSurfaceFinding
import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservedComponent
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.PrivacyImpact
import cz.davidstrnadel.aura.core.RoleCategory
import java.util.Locale

class DefensiveSurfaceAuditor {
    fun audit(assessments: List<AuraAssessment>): List<DefensiveSurfaceFinding> =
        assessments.flatMap { assessment ->
            auditOne(assessment.snapshot, assessment.role.predicted)
        }.sortedWith(compareBy({ it.packageName }, { it.findingType.name }))

    private fun auditOne(snapshot: ObservedAppSnapshot, role: RoleCategory): List<DefensiveSurfaceFinding> {
        val findings = mutableListOf<DefensiveSurfaceFinding>()
        val isSensitiveRole = role in sensitiveRoles
        val actionability = actionability(snapshot)

        if (isSensitiveRole && snapshot.rawFeatures["debuggable"] == "true") {
            findings += finding(
                snapshot = snapshot,
                type = DefensiveFindingType.DEBUGGABLE_SENSITIVE_APP,
                severity = DefensiveFindingSeverity.HIGH,
                actionability = actionability,
                source = EvidenceSource.PACKAGE_MANAGER,
                rawValue = "debuggable=true;role=$role",
                normalizedValue = "debuggable-sensitive-app",
                confidence = 0.92,
                explanation = "A sensitive-role app is debuggable. This is observable from app metadata, but whether it is only a lab/debug build must be interpreted by the evaluator."
            )
        }

        if (isSensitiveRole && snapshot.rawFeatures["allowBackup"] == "true") {
            findings += finding(
                snapshot = snapshot,
                type = DefensiveFindingType.BACKUP_ALLOWED_SENSITIVE_APP,
                severity = DefensiveFindingSeverity.MEDIUM,
                actionability = actionability,
                source = EvidenceSource.PACKAGE_MANAGER,
                rawValue = "allowBackup=true;role=$role",
                normalizedValue = "backup-allowed-sensitive-app",
                confidence = 0.88,
                explanation = "A sensitive-role app allows Android backup. AURA records this as defensive-surface evidence, not as malware evidence."
            )
        }

        if (snapshot.rawFeatures["usesCleartextTraffic"] == "true" && isSensitiveRole) {
            findings += finding(
                snapshot = snapshot,
                type = DefensiveFindingType.CLEARTEXT_TRAFFIC_ALLOWED,
                severity = DefensiveFindingSeverity.MEDIUM,
                actionability = actionability,
                source = EvidenceSource.PACKAGE_MANAGER,
                rawValue = "usesCleartextTraffic=true;networkSecurityConfig=not-parsed-on-device",
                normalizedValue = "cleartext-traffic-allowed",
                confidence = 0.70,
                explanation = "Best-effort cleartext traffic allowance is observable on device. Detailed network_security_config parsing belongs to the offline APK analyzer."
            )
        }

        val unprotectedExported = snapshot.components.filter { it.isUnprotectedExportedSurface() }
        if (unprotectedExported.isNotEmpty()) {
            findings += finding(
                snapshot = snapshot,
                type = DefensiveFindingType.UNPROTECTED_EXPORTED_COMPONENT,
                severity = if (unprotectedExported.any { it.type == "provider" || it.type == "service" }) {
                    DefensiveFindingSeverity.HIGH
                } else {
                    DefensiveFindingSeverity.MEDIUM
                },
                actionability = actionability,
                source = EvidenceSource.MANIFEST_COMPONENT,
                rawValue = unprotectedExported.joinToString(";") { "${it.type}:${it.name}" },
                normalizedValue = "unprotected-exported-component",
                confidence = 0.86,
                explanation = "The app exposes non-launcher components without a component-level permission. AURA can observe the manifest surface, but semantic exploitability requires manual or offline analysis."
            )
        }

        return findings
    }

    private fun ObservedComponent.isUnprotectedExportedSurface(): Boolean =
        exported && permission.isNullOrBlank() && !isLauncherEntryPoint

    private fun actionability(snapshot: ObservedAppSnapshot): ActionabilityClass = when {
        snapshot.isSystemApp || snapshot.isPrivilegedApp -> ActionabilityClass.OEM_OR_PLATFORM_ONLY
        else -> ActionabilityClass.USER_CAN_ONLY_REVIEW
    }

    private fun finding(
        snapshot: ObservedAppSnapshot,
        type: DefensiveFindingType,
        severity: DefensiveFindingSeverity,
        actionability: ActionabilityClass,
        source: EvidenceSource,
        rawValue: String,
        normalizedValue: String,
        confidence: Double,
        explanation: String
    ): DefensiveSurfaceFinding {
        val evidence = EvidenceFactory.item(
            source = source,
            rawValue = rawValue,
            normalizedValue = normalizedValue,
            confidence = confidence,
            observabilityState = ObservabilityState.OBSERVED_ENABLED,
            privacyImpact = PrivacyImpact.APP_METADATA,
            supports = listOf("defensive.${type.name.lowercase(Locale.US)}"),
            humanExplanation = explanation
        )
        return DefensiveSurfaceFinding(
            findingId = "def_" + listOf(snapshot.packageName, type.name)
                .joinToString("_")
                .lowercase(Locale.US)
                .replace(Regex("[^a-z0-9_]+"), "_")
                .trim('_'),
            packageName = snapshot.packageName,
            findingType = type,
            severity = severity,
            confidence = confidence.coerceIn(0.0, 1.0),
            observabilityState = ObservabilityState.OBSERVED_ENABLED,
            actionabilityClass = actionability,
            evidence = listOf(evidence),
            humanExplanation = explanation
        )
    }

    companion object {
        private val sensitiveRoles = setOf(
            RoleCategory.PAYMENT_BANKING,
            RoleCategory.DEVICE_MANAGEMENT,
            RoleCategory.KEYBOARD,
            RoleCategory.VPN_SECURITY_APP
        )
    }
}
