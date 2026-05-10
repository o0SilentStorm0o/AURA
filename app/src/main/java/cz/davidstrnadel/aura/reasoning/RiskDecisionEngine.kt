package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ActionabilityClass
import cz.davidstrnadel.aura.core.AuraDecision
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.ProvenanceClass
import cz.davidstrnadel.aura.core.RecommendedAction
import cz.davidstrnadel.aura.core.RemediationScope
import cz.davidstrnadel.aura.core.RiskVector
import cz.davidstrnadel.aura.core.RoleCategory
import cz.davidstrnadel.aura.core.clampedScore
import kotlin.math.max

data class RiskDecisionResult(
    val riskVector: RiskVector,
    val decision: AuraDecision,
    val evidence: List<EvidenceItem>
)

class RiskDecisionEngine(
    private val assets: AuraRuleAssets = AuraRuleAssets()
) {
    fun decide(
        snapshot: ObservedAppSnapshot,
        role: RoleCategory,
        roleConfidence: Double,
        provenanceClass: ProvenanceClass,
        provenanceConfidence: Double
    ): RiskDecisionResult {
        val harm = harmPotential(snapshot)
        val activeRiskyCapability = hasActiveRiskyCapability(snapshot)
        val legitimacy = legitimacyFit(snapshot, role, roleConfidence)
        val actionabilityClass = actionability(snapshot)
        val actionability = actionabilityScore(actionabilityClass)
        val abuseEvidence = abuseEvidence(snapshot, provenanceClass, activeRiskyCapability)
        val uncertainty = uncertainty(snapshot, roleConfidence, provenanceConfidence)

        val vector = RiskVector(
            harm = harm,
            legitimacy = legitimacy,
            abuseEvidence = abuseEvidence,
            provenanceConfidence = provenanceConfidence,
            actionability = actionability,
            uncertainty = uncertainty
        )

        val evidence = EvidenceFactory.item(
            source = EvidenceSource.DECISION_POLICY,
            rawValue = "harm=$harm;legitimacy=$legitimacy;abuse=$abuseEvidence;actionability=$actionability;uncertainty=$uncertainty",
            normalizedValue = "risk-vector",
            confidence = 0.88,
            observabilityState = ObservabilityState.OBSERVED_ENABLED,
            supports = listOf("risk.vector"),
            humanExplanation = "AURA separates capability exposure, role legitimacy, provenance confidence, abuse evidence, user actionability, and uncertainty."
        )

        val baseDecision = when {
            harm >= 0.70 && abuseEvidence >= 0.65 && legitimacy < 0.50 && activeRiskyCapability && actionability >= 0.65 ->
                AuraDecision(
                    color = DecisionColor.RED,
                    userAlert = true,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "User-actionable threat",
                    explanation = "High capability exposure is paired with concrete abuse evidence, low role legitimacy, active risky capability, and high user actionability.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            harm < 0.20 && snapshot.isSystemApp && abuseEvidence < 0.35 ->
                AuraDecision(
                    color = DecisionColor.GREEN,
                    userAlert = false,
                    expertFinding = false,
                    actionabilityClass = actionabilityClass,
                    title = "Expected low-exposure platform component",
                    explanation = "This system component has low observed capability exposure and no concrete abuse evidence.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            harm < 0.30 &&
                abuseEvidence < 0.35 &&
                role in setOf(RoleCategory.UNKNOWN_SIDELOAD, RoleCategory.UNKNOWN_UTILITY) &&
                provenanceClass in setOf(ProvenanceClass.UNKNOWN_SIDELOAD, ProvenanceClass.UNKNOWN) ->
                AuraDecision(
                    color = DecisionColor.GRAY,
                    userAlert = false,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "Unknown low-exposure app",
                    explanation = "Unknown provenance without active risky capability or concrete abuse evidence is treated as uncertainty, not maliciousness.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            legitimacy >= 0.70 && provenanceConfidence >= 0.62 && abuseEvidence < 0.35 ->
                AuraDecision(
                    color = DecisionColor.GREEN,
                    userAlert = false,
                    expertFinding = false,
                    actionabilityClass = actionabilityClass,
                    title = "Expected for role",
                    explanation = "Observed capabilities are plausible for the inferred role and no abuse evidence is present.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            harm >= 0.55 &&
                actionability < 0.55 &&
                provenanceClass in platformAuditClasses &&
                (legitimacy < 0.75 || provenanceConfidence < 0.65) ->
                AuraDecision(
                    color = DecisionColor.BLUE,
                    userAlert = false,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "Platform/OEM audit finding",
                    explanation = "Exposure may matter to a researcher or administrator, but this is not an immediate user panic alert.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            uncertainty >= 0.62 && abuseEvidence < 0.45 ->
                AuraDecision(
                    color = DecisionColor.GRAY,
                    userAlert = false,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "Insufficient evidence",
                    explanation = "Unknown evidence increases uncertainty rather than being treated as malicious.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            else ->
                AuraDecision(
                    color = DecisionColor.YELLOW,
                    userAlert = false,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "Review recommended",
                    explanation = "AURA found a capability/provenance/role mismatch that deserves review, but not a panic alert.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
        }
        val decision = baseDecision.copy(
            recommendedActions = recommendedActions(
                snapshot = snapshot,
                color = baseDecision.color,
                actionabilityClass = actionabilityClass,
                provenanceClass = provenanceClass,
                activeRiskyCapability = activeRiskyCapability
            )
        )

        return RiskDecisionResult(vector, decision, listOf(evidence))
    }

    private fun harmPotential(snapshot: ObservedAppSnapshot): Double {
        val permissionScore = snapshot.requestedPermissions.maxOfOrNull { assets.permissionHarm[it] ?: 0.0 } ?: 0.0
        val grantedBoost = if (snapshot.grantedPermissions.any { (assets.permissionHarm[it] ?: 0.0) >= 0.75 }) 0.10 else 0.0
        val specialBoost = if (hasActiveRiskyCapability(snapshot)) 0.25 else 0.0
        val persistenceBoost = if (snapshot.requestedPermissions.any { it.endsWith("RECEIVE_BOOT_COMPLETED") }) 0.10 else 0.0
        return max(permissionScore, specialBoost + persistenceBoost + grantedBoost).clampedScore()
    }

    private fun legitimacyFit(snapshot: ObservedAppSnapshot, role: RoleCategory, roleConfidence: Double): Double {
        val dangerous = snapshot.requestedPermissions.toSet()
        val expected = when (role) {
            RoleCategory.CAMERA -> dangerous.any { it.endsWith("CAMERA") || it.endsWith("RECORD_AUDIO") }
            RoleCategory.MAPS_NAVIGATION -> dangerous.any { it.endsWith("ACCESS_FINE_LOCATION") || it.endsWith("ACCESS_COARSE_LOCATION") }
            RoleCategory.ACCESSIBILITY_TOOL -> snapshot.specialAccess["accessibility_service"] != null
            RoleCategory.KEYBOARD -> snapshot.components.any { it.permission == "android.permission.BIND_INPUT_METHOD" }
            RoleCategory.VPN_SECURITY_APP -> snapshot.components.any { it.name.contains("Vpn", ignoreCase = true) }
            RoleCategory.BROWSER -> snapshot.packageName.contains("browser", true) || snapshot.packageName.contains("chrome", true)
            RoleCategory.DIALER -> dangerous.any { it.endsWith("CALL_PHONE") || it.endsWith("READ_PHONE_STATE") }
            RoleCategory.PAYMENT_BANKING -> true
            RoleCategory.SYSTEM_COMPONENT, RoleCategory.OEM_TELEMETRY_SERVICE -> snapshot.isSystemApp
            else -> false
        }
        return when {
            expected -> max(0.72, roleConfidence).clampedScore()
            role == RoleCategory.UNKNOWN_SIDELOAD -> 0.18
            role == RoleCategory.UNKNOWN_UTILITY -> 0.32
            else -> (roleConfidence * 0.72).clampedScore()
        }
    }

    private fun abuseEvidence(
        snapshot: ObservedAppSnapshot,
        provenanceClass: ProvenanceClass,
        activeRiskyCapability: Boolean
    ): Double {
        val sideload = provenanceClass == ProvenanceClass.UNKNOWN_SIDELOAD
        val multiSpecial = snapshot.specialAccess.values.count { it == ObservabilityState.OBSERVED_ENABLED } >= 2
        val persistence = snapshot.requestedPermissions.any { it.endsWith("RECEIVE_BOOT_COMPLETED") }
        return when {
            sideload && activeRiskyCapability && multiSpecial -> 0.86
            sideload && activeRiskyCapability -> 0.72
            sideload && persistence -> 0.48
            activeRiskyCapability && provenanceClass == ProvenanceClass.UNKNOWN -> 0.46
            activeRiskyCapability -> 0.34
            else -> 0.12
        }
    }

    private fun uncertainty(
        snapshot: ObservedAppSnapshot,
        roleConfidence: Double,
        provenanceConfidence: Double
    ): Double {
        val unknownStates = snapshot.specialAccess.values.count {
            it == ObservabilityState.UNKNOWN_API_LIMITATION ||
                it == ObservabilityState.NOT_OBSERVABLE ||
                it == ObservabilityState.USER_GRANT_REQUIRED
        }
        val observabilityPenalty = (unknownStates * 0.08).coerceAtMost(0.24)
        return (1.0 - ((roleConfidence + provenanceConfidence) / 2.0) + observabilityPenalty).clampedScore()
    }

    private fun hasActiveRiskyCapability(snapshot: ObservedAppSnapshot): Boolean =
        snapshot.specialAccess.any { (name, state) ->
            name in activeRiskySpecialAccess && state == ObservabilityState.OBSERVED_ENABLED
        }

    private fun actionability(snapshot: ObservedAppSnapshot): ActionabilityClass = when {
        snapshot.specialAccess.values.any { it == ObservabilityState.OBSERVED_ENABLED } ->
            ActionabilityClass.USER_CAN_DISABLE_SPECIAL_ACCESS
        snapshot.grantedPermissions.any { assets.permissionHarm.containsKey(it) } && !snapshot.isSystemApp ->
            ActionabilityClass.USER_CAN_REVOKE_PERMISSION
        !snapshot.isSystemApp ->
            ActionabilityClass.USER_CAN_UNINSTALL
        snapshot.isSystemApp || snapshot.isPrivilegedApp ->
            ActionabilityClass.OEM_OR_PLATFORM_ONLY
        else ->
            ActionabilityClass.USER_CAN_ONLY_REVIEW
    }

    private fun actionabilityScore(actionabilityClass: ActionabilityClass): Double = when (actionabilityClass) {
        ActionabilityClass.USER_CAN_REVOKE_PERMISSION -> 0.72
        ActionabilityClass.USER_CAN_DISABLE_SPECIAL_ACCESS -> 0.86
        ActionabilityClass.USER_CAN_UNINSTALL -> 0.82
        ActionabilityClass.USER_CAN_ONLY_REVIEW -> 0.42
        ActionabilityClass.OEM_OR_PLATFORM_ONLY -> 0.18
        ActionabilityClass.REQUIRES_ENTERPRISE_ADMIN -> 0.28
        ActionabilityClass.NOT_ACTIONABLE -> 0.0
    }

    private fun recommendedActions(
        snapshot: ObservedAppSnapshot,
        color: DecisionColor,
        actionabilityClass: ActionabilityClass,
        provenanceClass: ProvenanceClass,
        activeRiskyCapability: Boolean
    ): List<RecommendedAction> = when (color) {
        DecisionColor.RED -> redActions(snapshot, actionabilityClass, activeRiskyCapability)
        DecisionColor.BLUE -> listOf(
            RecommendedAction(
                actionId = "audit_platform_component",
                title = "Audit as platform finding",
                description = "Treat this as an expert or OEM/platform audit item. It is intentionally excluded from the primary panic alert queue.",
                actionabilityClass = ActionabilityClass.OEM_OR_PLATFORM_ONLY,
                scope = RemediationScope.EXPERT_AUDIT,
                userFacing = false
            )
        )
        DecisionColor.GRAY -> grayActions(snapshot)
        DecisionColor.YELLOW -> reviewActions(snapshot, actionabilityClass, provenanceClass)
        DecisionColor.GREEN -> listOf(
            RecommendedAction(
                actionId = "no_user_action_required",
                title = "No user action required",
                description = "Observed capabilities fit the inferred role and there is no concrete abuse evidence in this scan.",
                actionabilityClass = ActionabilityClass.NOT_ACTIONABLE,
                scope = RemediationScope.NONE,
                userFacing = false
            )
        )
    }

    private fun redActions(
        snapshot: ObservedAppSnapshot,
        actionabilityClass: ActionabilityClass,
        activeRiskyCapability: Boolean
    ): List<RecommendedAction> {
        val actions = mutableListOf<RecommendedAction>()
        if (activeRiskyCapability) {
            actions += RecommendedAction(
                actionId = "disable_risky_special_access",
                title = "Disable risky special access",
                description = "Review and disable active Accessibility, notification listener, or overlay access for this app before interacting with sensitive apps.",
                actionabilityClass = ActionabilityClass.USER_CAN_DISABLE_SPECIAL_ACCESS,
                scope = RemediationScope.USER,
                userFacing = true
            )
        }
        if (!snapshot.isSystemApp) {
            actions += RecommendedAction(
                actionId = "uninstall_or_disable_app",
                title = "Uninstall or disable the app",
                description = "The app is user-removable in this scan context; uninstalling removes the observed active abuse surface.",
                actionabilityClass = ActionabilityClass.USER_CAN_UNINSTALL,
                scope = RemediationScope.USER,
                userFacing = true,
                destructive = true
            )
        }
        actions += RecommendedAction(
            actionId = "export_scan_for_review",
            title = "Export evidence for review",
            description = "Keep the local JSON export so the alert can be reproduced from raw features, evidence IDs, and the risk vector.",
            actionabilityClass = actionabilityClass,
            scope = RemediationScope.RESEARCH,
            userFacing = false
        )
        return actions
    }

    private fun grayActions(snapshot: ObservedAppSnapshot): List<RecommendedAction> {
        val actions = mutableListOf(
            RecommendedAction(
                actionId = "abstain_collect_more_context",
                title = "Collect more context",
                description = "Unknown evidence is represented as uncertainty. Rescan after relevant user grants or controlled scenario setup if stronger evidence is needed.",
                actionabilityClass = ActionabilityClass.USER_CAN_ONLY_REVIEW,
                scope = RemediationScope.RESEARCH,
                userFacing = true
            )
        )
        if (snapshot.rawFeatures["usageStatsObservability"] == ObservabilityState.USER_GRANT_REQUIRED.name) {
            actions += RecommendedAction(
                actionId = "optional_usage_stats_opt_in",
                title = "Optionally enable Usage Access for research",
                description = "Usage Access can improve temporal episode evidence, but AURA must still treat missing UsageStats as uncertainty rather than maliciousness.",
                actionabilityClass = ActionabilityClass.USER_CAN_ONLY_REVIEW,
                scope = RemediationScope.RESEARCH,
                userFacing = true
            )
        }
        return actions
    }

    private fun reviewActions(
        snapshot: ObservedAppSnapshot,
        actionabilityClass: ActionabilityClass,
        provenanceClass: ProvenanceClass
    ): List<RecommendedAction> {
        val actions = mutableListOf(
            RecommendedAction(
                actionId = "review_role_capability_mismatch",
                title = "Review role/capability mismatch",
                description = "Inspect the package role, requested capabilities, provenance evidence, and active special-access states before escalating.",
                actionabilityClass = actionabilityClass,
                scope = RemediationScope.USER,
                userFacing = true
            )
        )
        if (!snapshot.isSystemApp) {
            actions += RecommendedAction(
                actionId = "review_revocable_permissions",
                title = "Review revocable permissions",
                description = "If the app is not needed, revoke risky runtime permissions or uninstall it. Do not treat unknown provenance alone as malware.",
                actionabilityClass = ActionabilityClass.USER_CAN_REVOKE_PERMISSION,
                scope = RemediationScope.USER,
                userFacing = true
            )
        }
        if (provenanceClass in platformAuditClasses) {
            actions += RecommendedAction(
                actionId = "escalate_to_platform_audit_if_needed",
                title = "Escalate as platform audit if needed",
                description = "For system or OEM components, prefer expert audit handling over end-user panic unless concrete abuse evidence appears.",
                actionabilityClass = ActionabilityClass.OEM_OR_PLATFORM_ONLY,
                scope = RemediationScope.EXPERT_AUDIT,
                userFacing = false
            )
        }
        return actions
    }

    companion object {
        private val activeRiskySpecialAccess = setOf(
            "accessibility_service",
            "notification_listener",
            "overlay"
        )

        private val platformAuditClasses = setOf(
            ProvenanceClass.AOSP_KNOWN,
            ProvenanceClass.GOOGLE_KNOWN,
            ProvenanceClass.OEM_SIGNED_SYSTEM,
            ProvenanceClass.OPAQUE_PRIVILEGED,
            ProvenanceClass.CARRIER_COMPONENT,
            ProvenanceClass.THIRD_PARTY_PREINSTALL
        )

        val permissionHarm = AuraRuleAssets.DEFAULT_PERMISSION_HARM
    }
}
