package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ActionabilityClass
import cz.davidstrnadel.aura.core.AuraDecision
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.DecisionCounterfactual
import cz.davidstrnadel.aura.core.DecisionInvariantCheck
import cz.davidstrnadel.aura.core.DecisionTrace
import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.EvaluatedPolicyRule
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.ProvenanceClass
import cz.davidstrnadel.aura.core.RecommendedAction
import cz.davidstrnadel.aura.core.RejectedDecisionAlternative
import cz.davidstrnadel.aura.core.RemediationScope
import cz.davidstrnadel.aura.core.RiskVector
import cz.davidstrnadel.aura.core.RoleCategory
import cz.davidstrnadel.aura.core.UserRiskStory
import cz.davidstrnadel.aura.core.clampedScore
import java.util.Locale
import kotlin.math.max
import kotlin.math.min

data class RiskDecisionResult(
    val riskVector: RiskVector,
    val decision: AuraDecision,
    val decisionTrace: DecisionTrace,
    val userRiskStory: UserRiskStory,
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
        val provenanceTrust = provenanceTrust(provenanceClass, provenanceConfidence)
        val uncertainty = uncertainty(snapshot, roleConfidence, provenanceTrust)

        val vector = RiskVector(
            harm = harm,
            legitimacy = legitimacy,
            abuseEvidence = abuseEvidence,
            provenanceConfidence = provenanceConfidence,
            provenanceTrust = provenanceTrust,
            actionability = actionability,
            uncertainty = uncertainty
        )

        val evidence = EvidenceFactory.item(
            source = EvidenceSource.DECISION_POLICY,
            rawValue = "harm=$harm;legitimacy=$legitimacy;abuse=$abuseEvidence;provenanceClassificationConfidence=$provenanceConfidence;provenanceTrust=$provenanceTrust;actionability=$actionability;uncertainty=$uncertainty",
            normalizedValue = "risk-vector",
            confidence = 0.88,
            observabilityState = ObservabilityState.OBSERVED_ENABLED,
            supports = listOf("risk.vector"),
            humanExplanation = "AURA separates capability exposure, role legitimacy, provenance classification confidence, provenance trust, abuse evidence, user actionability, and uncertainty."
        )

        val ruleInputs = ruleInputs(
            harm = harm,
            legitimacy = legitimacy,
            abuseEvidence = abuseEvidence,
            provenanceConfidence = provenanceConfidence,
            provenanceTrust = provenanceTrust,
            actionability = actionability,
            uncertainty = uncertainty,
            activeRiskyCapability = activeRiskyCapability,
            role = role,
            provenanceClass = provenanceClass,
            isSystemApp = snapshot.isSystemApp
        )
        val redMatched = harm >= 0.70 &&
            abuseEvidence >= 0.65 &&
            legitimacy < 0.50 &&
            activeRiskyCapability &&
            actionability >= 0.65
        val greenLowExposurePlatformMatched = harm < 0.20 && snapshot.isSystemApp && abuseEvidence < 0.35
        val grayUnknownLowExposureMatched = harm < 0.30 &&
            abuseEvidence < 0.35 &&
            role in setOf(RoleCategory.UNKNOWN_SIDELOAD, RoleCategory.UNKNOWN_UTILITY) &&
            provenanceClass in setOf(ProvenanceClass.UNKNOWN_SIDELOAD, ProvenanceClass.UNKNOWN)
        val greenExpectedRoleMatched = legitimacy >= 0.70 && provenanceTrust >= 0.62 && abuseEvidence < 0.35
        val bluePlatformAuditMatched = harm >= 0.55 &&
            actionability < 0.55 &&
            provenanceClass in platformAuditClasses &&
            (legitimacy < 0.75 || provenanceTrust < 0.65)
        val grayUncertaintyMatched = uncertainty >= 0.62 && abuseEvidence < 0.45
        val evaluatedRules = listOf(
            policyRule(
                "RED_USER_ACTIONABLE_THREAT",
                "RED user-actionable threat",
                redMatched,
                ruleInputs,
                "Requires high harm, concrete abuse evidence, low role legitimacy, active risky capability, and high user actionability."
            ),
            policyRule(
                "GREEN_LOW_EXPOSURE_PLATFORM",
                "GREEN low-exposure platform component",
                greenLowExposurePlatformMatched,
                ruleInputs,
                "Low-exposure system components without abuse evidence are not user alerts."
            ),
            policyRule(
                "GRAY_UNKNOWN_LOW_EXPOSURE",
                "GRAY unknown low-exposure app",
                grayUnknownLowExposureMatched,
                ruleInputs,
                "Unknown provenance without active risky capability is uncertainty, not maliciousness."
            ),
            policyRule(
                "GREEN_EXPECTED_ROLE",
                "GREEN expected for role",
                greenExpectedRoleMatched,
                ruleInputs,
                "Capabilities fit the inferred role and abuse evidence is low."
            ),
            policyRule(
                "BLUE_PLATFORM_AUDIT",
                "BLUE platform/OEM audit finding",
                bluePlatformAuditMatched,
                ruleInputs,
                "High exposure with low user actionability is separated from the primary panic queue."
            ),
            policyRule(
                "GRAY_HIGH_UNCERTAINTY",
                "GRAY high uncertainty",
                grayUncertaintyMatched,
                ruleInputs,
                "High uncertainty without concrete abuse evidence should abstain."
            )
        )

        val baseDecision = when {
            redMatched ->
                AuraDecision(
                    color = DecisionColor.RED,
                    userAlert = true,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "User-actionable threat",
                    explanation = "High capability exposure is paired with concrete abuse evidence, low role legitimacy, active risky capability, and high user actionability.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            greenLowExposurePlatformMatched ->
                AuraDecision(
                    color = DecisionColor.GREEN,
                    userAlert = false,
                    expertFinding = false,
                    actionabilityClass = actionabilityClass,
                    title = "Expected low-exposure platform component",
                    explanation = "This system component has low observed capability exposure and no concrete abuse evidence.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            grayUnknownLowExposureMatched ->
                AuraDecision(
                    color = DecisionColor.GRAY,
                    userAlert = false,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "Unknown low-exposure app",
                    explanation = "Unknown provenance without active risky capability or concrete abuse evidence is treated as uncertainty, not maliciousness.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            greenExpectedRoleMatched ->
                AuraDecision(
                    color = DecisionColor.GREEN,
                    userAlert = false,
                    expertFinding = false,
                    actionabilityClass = actionabilityClass,
                    title = "Expected for role",
                    explanation = "Observed capabilities are plausible for the inferred role and no abuse evidence is present.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            bluePlatformAuditMatched ->
                AuraDecision(
                    color = DecisionColor.BLUE,
                    userAlert = false,
                    expertFinding = true,
                    actionabilityClass = actionabilityClass,
                    title = "Platform/OEM audit finding",
                    explanation = "Exposure may matter to a researcher or administrator, but this is not an immediate user panic alert.",
                    evidenceIds = listOf(evidence.evidenceId)
                )
            grayUncertaintyMatched ->
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
        val decisionTrace = decisionTrace(
            decision = decision,
            evaluatedRules = evaluatedRules,
            thresholdInputs = ruleInputs,
            activeRiskyCapability = activeRiskyCapability,
            abuseEvidence = abuseEvidence,
            legitimacy = legitimacy,
            actionability = actionability,
            uncertainty = uncertainty,
            snapshot = snapshot
        )
        val userRiskStory = userRiskStory(
            snapshot = snapshot,
            decision = decision,
            role = role,
            provenanceClass = provenanceClass,
            vector = vector,
            activeRiskyCapability = activeRiskyCapability
        )

        return RiskDecisionResult(vector, decision, decisionTrace, userRiskStory, listOf(evidence))
    }

    private fun ruleInputs(
        harm: Double,
        legitimacy: Double,
        abuseEvidence: Double,
        provenanceConfidence: Double,
        provenanceTrust: Double,
        actionability: Double,
        uncertainty: Double,
        activeRiskyCapability: Boolean,
        role: RoleCategory,
        provenanceClass: ProvenanceClass,
        isSystemApp: Boolean
    ): Map<String, String> = mapOf(
        "harm" to harm.scoreText(),
        "legitimacy" to legitimacy.scoreText(),
        "abuseEvidence" to abuseEvidence.scoreText(),
        "provenanceClassificationConfidence" to provenanceConfidence.scoreText(),
        "provenanceTrust" to provenanceTrust.scoreText(),
        "actionability" to actionability.scoreText(),
        "uncertainty" to uncertainty.scoreText(),
        "activeRiskyCapability" to activeRiskyCapability.toString(),
        "role" to role.name,
        "provenanceClass" to provenanceClass.name,
        "isSystemApp" to isSystemApp.toString()
    )

    private fun policyRule(
        ruleId: String,
        ruleName: String,
        matched: Boolean,
        inputs: Map<String, String>,
        explanation: String
    ): EvaluatedPolicyRule =
        EvaluatedPolicyRule(
            ruleId = ruleId,
            ruleName = ruleName,
            matched = matched,
            inputs = inputs,
            explanation = explanation
        )

    private fun decisionTrace(
        decision: AuraDecision,
        evaluatedRules: List<EvaluatedPolicyRule>,
        thresholdInputs: Map<String, String>,
        activeRiskyCapability: Boolean,
        abuseEvidence: Double,
        legitimacy: Double,
        actionability: Double,
        uncertainty: Double,
        snapshot: ObservedAppSnapshot
    ): DecisionTrace =
        DecisionTrace(
            policyVersion = assets.decisionPolicyVersion,
            evaluatedRules = evaluatedRules,
            selectedDecision = decision.color,
            rejectedAlternatives = rejectedAlternatives(decision.color, evaluatedRules),
            thresholdInputs = thresholdInputs,
            counterfactuals = counterfactuals(decision.color, activeRiskyCapability, snapshot),
            invariantChecks = invariantChecks(
                decision = decision,
                activeRiskyCapability = activeRiskyCapability,
                abuseEvidence = abuseEvidence,
                legitimacy = legitimacy,
                actionability = actionability,
                uncertainty = uncertainty,
                snapshot = snapshot
            )
        )

    private fun rejectedAlternatives(
        selected: DecisionColor,
        evaluatedRules: List<EvaluatedPolicyRule>
    ): List<RejectedDecisionAlternative> =
        evaluatedRules
            .filter { !it.matched }
            .mapNotNull { rule ->
                val color = when {
                    rule.ruleId.startsWith("RED") -> DecisionColor.RED
                    rule.ruleId.startsWith("GREEN") -> DecisionColor.GREEN
                    rule.ruleId.startsWith("BLUE") -> DecisionColor.BLUE
                    rule.ruleId.startsWith("GRAY") -> DecisionColor.GRAY
                    else -> null
                }
                color?.takeIf { it != selected }?.let {
                    RejectedDecisionAlternative(
                        decisionColor = it,
                        reason = "Policy rule ${rule.ruleId} did not match.",
                        blockingInputs = rule.inputs
                    )
                }
            }
            .distinctBy { it.decisionColor }

    private fun counterfactuals(
        selected: DecisionColor,
        activeRiskyCapability: Boolean,
        snapshot: ObservedAppSnapshot
    ): List<DecisionCounterfactual> = when (selected) {
        DecisionColor.RED -> listOf(
            DecisionCounterfactual(
                targetDecision = DecisionColor.YELLOW,
                requiredChanges = buildList {
                    if (activeRiskyCapability) {
                        add("Disable active risky special access such as Accessibility, notification listener, or overlay.")
                    }
                }.ifEmpty { listOf("Remove concrete abuse evidence while preserving the raw export for review.") },
                userActionable = true
            ),
            DecisionCounterfactual(
                targetDecision = DecisionColor.GRAY,
                requiredChanges = listOf("Remove active abuse evidence while leaving provenance or role evidence unresolved."),
                userActionable = false
            )
        )
        DecisionColor.BLUE -> listOf(
            DecisionCounterfactual(
                targetDecision = DecisionColor.RED,
                requiredChanges = listOf(
                    "Observe concrete abuse evidence.",
                    "Observe high user actionability rather than platform-only actionability.",
                    "Observe an active risky capability."
                ),
                userActionable = false
            )
        )
        DecisionColor.GRAY -> listOf(
            DecisionCounterfactual(
                targetDecision = DecisionColor.YELLOW,
                requiredChanges = listOf("Collect additional role, provenance, or special-access evidence."),
                userActionable = true
            )
        )
        DecisionColor.GREEN -> listOf(
            DecisionCounterfactual(
                targetDecision = DecisionColor.YELLOW,
                requiredChanges = listOf("Observe a role/capability mismatch or weaker provenance evidence."),
                userActionable = false
            )
        )
        DecisionColor.YELLOW -> listOf(
            DecisionCounterfactual(
                targetDecision = DecisionColor.RED,
                requiredChanges = listOf(
                    "Observe concrete abuse evidence.",
                    "Observe active risky capability.",
                    "Confirm that the user can revoke or remove the risky capability."
                ),
                userActionable = false
            ),
            DecisionCounterfactual(
                targetDecision = DecisionColor.GREEN,
                requiredChanges = listOf("Increase role legitimacy and keep abuse evidence low."),
                userActionable = false
            )
        )
    }

    private fun invariantChecks(
        decision: AuraDecision,
        activeRiskyCapability: Boolean,
        abuseEvidence: Double,
        legitimacy: Double,
        actionability: Double,
        uncertainty: Double,
        snapshot: ObservedAppSnapshot
    ): List<DecisionInvariantCheck> = listOf(
        DecisionInvariantCheck(
            invariantId = "UNKNOWN_EVIDENCE_MUST_NOT_CREATE_RED",
            passed = decision.color != DecisionColor.RED ||
                (abuseEvidence >= 0.65 && legitimacy < 0.50 && actionability >= 0.65),
            explanation = "Unknown evidence can increase uncertainty, but RED requires concrete abuse evidence, low legitimacy, and high actionability."
        ),
        DecisionInvariantCheck(
            invariantId = "BLUE_MUST_NOT_BE_PRIMARY_USER_ALERT",
            passed = decision.color != DecisionColor.BLUE || !decision.userAlert,
            explanation = "BLUE findings are expert/platform audit findings and must stay out of the primary panic queue."
        ),
        DecisionInvariantCheck(
            invariantId = "RED_REQUIRES_ACTIVE_RISKY_CAPABILITY",
            passed = decision.color != DecisionColor.RED || activeRiskyCapability,
            explanation = "Declared-only risky capability is not enough for RED without an active risky capability."
        ),
        DecisionInvariantCheck(
            invariantId = "KNOWN_PACKAGE_IS_NOT_WHITELIST",
            passed = true,
            explanation = "Known package or provenance evidence contributes confidence but never bypasses risk evaluation."
        ),
        DecisionInvariantCheck(
            invariantId = "SYSTEM_APP_IS_NOT_AUTOMATICALLY_GREEN",
            passed = !snapshot.isSystemApp || decision.color != DecisionColor.GREEN || abuseEvidence < 0.35 || uncertainty < 0.80,
            explanation = "System app status is treated as provenance/context evidence, not as a hard safety whitelist."
        )
    )

    private fun userRiskStory(
        snapshot: ObservedAppSnapshot,
        decision: AuraDecision,
        role: RoleCategory,
        provenanceClass: ProvenanceClass,
        vector: RiskVector,
        activeRiskyCapability: Boolean
    ): UserRiskStory {
        val activeSpecialAccess = activeSpecialAccessNames(snapshot)
        val commonNotObserved = listOf(
            "AURA did not read screen contents.",
            "AURA did not read notification contents.",
            "AURA did not inspect network payloads.",
            "AURA did not perform root or kernel forensics."
        )
        return when (decision.color) {
            DecisionColor.RED -> UserRiskStory(
                headline = "Action required",
                severityLabel = "High user-actionable risk",
                primaryReason = "An app with unclear role/provenance has active risky access that can affect other apps.",
                whatWasObserved = listOf(
                    "Role: ${role.name}",
                    "Provenance: ${provenanceClass.name}",
                    "Active special access: ${activeSpecialAccess.ifEmpty { listOf("none") }.joinToString(", ")}",
                    "Risk vector: H=${vector.harm.scoreText()} E=${vector.abuseEvidence.scoreText()} A=${vector.actionability.scoreText()}"
                ),
                whatWasNotObserved = commonNotObserved,
                whyItMatters = "Active Accessibility, notification listener, or overlay access can become dangerous when paired with unclear provenance and low role legitimacy.",
                recommendedNextStep = "Disable the risky special access or uninstall the app if it is not needed.",
                confidenceText = "AURA has concrete active-capability evidence for this decision.",
                limitationsText = "This is not a malware payload verdict; it is a no-root risk and actionability assessment."
            )
            DecisionColor.BLUE -> UserRiskStory(
                headline = "Technical audit finding",
                severityLabel = "Expert/platform review",
                primaryReason = "The app has meaningful platform exposure, but ordinary user action is limited.",
                whatWasObserved = listOf(
                    "Role: ${role.name}",
                    "Provenance: ${provenanceClass.name}",
                    "User actionability is low.",
                    "Threat alert queue remains silent."
                ),
                whatWasNotObserved = commonNotObserved,
                whyItMatters = "Platform and OEM components can have high exposure without being appropriate user panic alerts.",
                recommendedNextStep = "Keep the local export for expert or platform review; do not remove system components casually.",
                confidenceText = "AURA separates platform audit value from immediate user danger.",
                limitationsText = "No-root apps cannot verify hidden OEM behavior or privileged allowlists completely."
            )
            DecisionColor.GRAY -> UserRiskStory(
                headline = "Insufficient evidence",
                severityLabel = "Uncertainty",
                primaryReason = "AURA does not have enough observable evidence to make a stronger claim.",
                whatWasObserved = listOf(
                    "Role: ${role.name}",
                    "Provenance: ${provenanceClass.name}",
                    "Uncertainty: ${vector.uncertainty.scoreText()}",
                    "Active risky capability: $activeRiskyCapability"
                ),
                whatWasNotObserved = commonNotObserved,
                whyItMatters = "Unknown evidence is not treated as malicious by default.",
                recommendedNextStep = "Collect more context, review the app source, or rescan after optional research grants if appropriate.",
                confidenceText = "AURA is intentionally abstaining instead of overclaiming.",
                limitationsText = "Missing evidence may reflect Android sandbox limits or flavor-specific package visibility."
            )
            DecisionColor.GREEN -> UserRiskStory(
                headline = "No user action required",
                severityLabel = "Expected for role",
                primaryReason = "Observed capabilities fit the inferred role and concrete abuse evidence is low.",
                whatWasObserved = listOf(
                    "Role: ${role.name}",
                    "Provenance: ${provenanceClass.name}",
                    "Legitimacy: ${vector.legitimacy.scoreText()}",
                    "Abuse evidence: ${vector.abuseEvidence.scoreText()}"
                ),
                whatWasNotObserved = commonNotObserved,
                whyItMatters = "Powerful permissions can be normal for apps such as cameras, maps, marketplace/delivery apps, keyboards, or system components.",
                recommendedNextStep = "No immediate user action is recommended from this scan evidence.",
                confidenceText = "AURA found no concrete abuse evidence for the current decision.",
                limitationsText = "GREEN threat status does not mean the app has perfect defensive posture."
            )
            DecisionColor.YELLOW -> UserRiskStory(
                headline = "Review recommended",
                severityLabel = "Needs review",
                primaryReason = "AURA found a capability, role, or provenance mismatch that does not justify a panic alert.",
                whatWasObserved = listOf(
                    "Role: ${role.name}",
                    "Provenance: ${provenanceClass.name}",
                    "Harm: ${vector.harm.scoreText()}",
                    "Legitimacy: ${vector.legitimacy.scoreText()}"
                ),
                whatWasNotObserved = commonNotObserved,
                whyItMatters = "Some elevated capabilities are legitimate, but the current evidence deserves user or expert review.",
                recommendedNextStep = "Review permissions, special access, installer source, and whether the app is still needed.",
                confidenceText = "AURA has review-worthy evidence but not enough concrete abuse evidence for RED.",
                limitationsText = "Manual context may be needed to distinguish unusual-but-legitimate apps from unwanted apps."
            )
        }
    }

    private fun activeSpecialAccessNames(snapshot: ObservedAppSnapshot): List<String> =
        snapshot.specialAccess
            .filterValues { it == ObservabilityState.OBSERVED_ENABLED }
            .keys
            .sorted()

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
            RoleCategory.ECOMMERCE_MARKETPLACE -> !hasActiveRiskyCapability(snapshot) && !hasUnexpectedHighRiskPermission(dangerous)
            RoleCategory.PUBLIC_INFORMATION -> !hasActiveRiskyCapability(snapshot) && !hasUnexpectedHighRiskPermission(dangerous)
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
        provenanceTrust: Double
    ): Double {
        val unknownStates = snapshot.specialAccess.values.count {
            it == ObservabilityState.UNKNOWN_API_LIMITATION ||
                it == ObservabilityState.NOT_OBSERVABLE ||
                it == ObservabilityState.USER_GRANT_REQUIRED
        }
        val observabilityPenalty = (unknownStates * 0.08).coerceAtMost(0.24)
        return (1.0 - ((roleConfidence + provenanceTrust) / 2.0) + observabilityPenalty).clampedScore()
    }

    private fun provenanceTrust(
        provenanceClass: ProvenanceClass,
        classificationConfidence: Double
    ): Double {
        val classTrustCeiling = when (provenanceClass) {
            ProvenanceClass.AOSP_KNOWN -> 0.88
            ProvenanceClass.GOOGLE_KNOWN -> 0.88
            ProvenanceClass.PLAY_INSTALLED -> 0.76
            ProvenanceClass.FDROID_OR_OPEN_SOURCE -> 0.72
            ProvenanceClass.OEM_SIGNED_SYSTEM -> 0.54
            ProvenanceClass.CARRIER_COMPONENT -> 0.46
            ProvenanceClass.THIRD_PARTY_PREINSTALL -> 0.42
            ProvenanceClass.OPAQUE_PRIVILEGED -> 0.34
            ProvenanceClass.UNKNOWN_SIDELOAD -> 0.18
            ProvenanceClass.UNKNOWN -> 0.24
        }
        return min(classTrustCeiling, classificationConfidence).clampedScore()
    }

    private fun hasActiveRiskyCapability(snapshot: ObservedAppSnapshot): Boolean =
        snapshot.specialAccess.any { (name, state) ->
            name in activeRiskySpecialAccess && state == ObservabilityState.OBSERVED_ENABLED
        }

    private fun hasUnexpectedHighRiskPermission(permissions: Set<String>): Boolean =
        permissions.any {
            it.endsWith("READ_SMS") ||
                it.endsWith("SEND_SMS") ||
                it.endsWith("RECEIVE_SMS") ||
                it.endsWith("READ_CALL_LOG") ||
                it.endsWith("REQUEST_INSTALL_PACKAGES") ||
                it.endsWith("SYSTEM_ALERT_WINDOW") ||
                it.endsWith("BIND_ACCESSIBILITY_SERVICE") ||
                it.endsWith("BIND_NOTIFICATION_LISTENER_SERVICE")
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

    private fun Double.scoreText(): String = String.format(Locale.US, "%.2f", this)
}
