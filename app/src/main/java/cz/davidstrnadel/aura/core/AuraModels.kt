package cz.davidstrnadel.aura.core

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class EvidenceItem(
    val evidenceId: String,
    val source: EvidenceSource,
    val rawValue: String,
    val normalizedValue: String,
    val confidence: Double,
    val observabilityState: ObservabilityState,
    val privacyImpact: PrivacyImpact,
    val supports: List<String>,
    val contradicts: List<String>,
    val humanExplanation: String
)

@JsonClass(generateAdapter = true)
data class ObservedComponent(
    val name: String,
    val type: String,
    val exported: Boolean,
    val permission: String?,
    val isLauncherEntryPoint: Boolean = false
)

@JsonClass(generateAdapter = true)
data class ObservedAppSnapshot(
    val snapshotId: String,
    val scanId: String,
    val collectedAt: Long,
    val apiLevel: Int,
    val androidVersion: String,
    val securityPatchLevel: String,
    val collectorVersion: String,
    val flavor: String,
    val deviceModel: String,
    val packageName: String,
    val appLabel: String,
    val versionName: String?,
    val versionCode: Long,
    val uid: Int,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val installerPackageName: String?,
    val sourceDir: String,
    val isSystemApp: Boolean,
    val isPrivilegedApp: Boolean,
    val isUpdatedSystemApp: Boolean,
    val requestedPermissions: List<String>,
    val grantedPermissions: List<String>,
    val signingCertDigestsSha256: List<String>,
    val components: List<ObservedComponent>,
    val specialAccess: Map<String, ObservabilityState>,
    val rawFeatures: Map<String, String>
)

@JsonClass(generateAdapter = true)
data class RoleInference(
    val predicted: RoleCategory,
    val confidence: Double,
    val evidenceIds: List<String>,
    val explanation: String
)

@JsonClass(generateAdapter = true)
data class ProvenanceAssessment(
    val provenanceClass: ProvenanceClass,
    val confidence: Double,
    val evidenceIds: List<String>,
    val explanation: String
)

@JsonClass(generateAdapter = true)
data class RiskVector(
    val harm: Double,
    val legitimacy: Double,
    val abuseEvidence: Double,
    val provenanceConfidence: Double,
    val actionability: Double,
    val uncertainty: Double
)

@JsonClass(generateAdapter = true)
data class RecommendedAction(
    val actionId: String,
    val title: String,
    val description: String,
    val actionabilityClass: ActionabilityClass,
    val scope: RemediationScope,
    val userFacing: Boolean,
    val destructive: Boolean = false
)

@JsonClass(generateAdapter = true)
data class AuraDecision(
    val color: DecisionColor,
    val userAlert: Boolean,
    val expertFinding: Boolean,
    val actionabilityClass: ActionabilityClass,
    val title: String,
    val explanation: String,
    val evidenceIds: List<String>,
    val recommendedActions: List<RecommendedAction> = emptyList()
)

@JsonClass(generateAdapter = true)
data class EvaluatedPolicyRule(
    val ruleId: String,
    val ruleName: String,
    val matched: Boolean,
    val inputs: Map<String, String>,
    val explanation: String
)

@JsonClass(generateAdapter = true)
data class RejectedDecisionAlternative(
    val decisionColor: DecisionColor,
    val reason: String,
    val blockingInputs: Map<String, String>
)

@JsonClass(generateAdapter = true)
data class DecisionCounterfactual(
    val targetDecision: DecisionColor,
    val requiredChanges: List<String>,
    val userActionable: Boolean
)

@JsonClass(generateAdapter = true)
data class DecisionInvariantCheck(
    val invariantId: String,
    val passed: Boolean,
    val explanation: String
)

@JsonClass(generateAdapter = true)
data class DecisionTrace(
    val policyVersion: String,
    val evaluatedRules: List<EvaluatedPolicyRule>,
    val selectedDecision: DecisionColor,
    val rejectedAlternatives: List<RejectedDecisionAlternative>,
    val thresholdInputs: Map<String, String>,
    val counterfactuals: List<DecisionCounterfactual>,
    val invariantChecks: List<DecisionInvariantCheck>
)

@JsonClass(generateAdapter = true)
data class UserRiskStory(
    val headline: String,
    val severityLabel: String,
    val primaryReason: String,
    val whatWasObserved: List<String>,
    val whatWasNotObserved: List<String>,
    val whyItMatters: String,
    val recommendedNextStep: String,
    val confidenceText: String,
    val limitationsText: String
)

@JsonClass(generateAdapter = true)
data class EvidenceGraphNode(
    val nodeId: String,
    val type: EvidenceGraphNodeType,
    val label: String,
    val value: String,
    val confidence: Double? = null
)

@JsonClass(generateAdapter = true)
data class EvidenceGraphEdge(
    val from: String,
    val to: String,
    val relation: EvidenceGraphRelation,
    val evidenceId: String? = null
)

@JsonClass(generateAdapter = true)
data class EvidenceGraph(
    val nodes: List<EvidenceGraphNode> = emptyList(),
    val edges: List<EvidenceGraphEdge> = emptyList()
)

@JsonClass(generateAdapter = true)
data class AuraAssessment(
    val snapshot: ObservedAppSnapshot,
    val evidence: List<EvidenceItem>,
    val role: RoleInference,
    val provenance: ProvenanceAssessment,
    val riskVector: RiskVector,
    val decision: AuraDecision,
    val decisionTrace: DecisionTrace,
    val userRiskStory: UserRiskStory,
    val evidenceGraph: EvidenceGraph = EvidenceGraph()
)

@JsonClass(generateAdapter = true)
data class DefensiveSurfaceFinding(
    val findingId: String,
    val packageName: String,
    val findingType: DefensiveFindingType,
    val severity: DefensiveFindingSeverity,
    val confidence: Double,
    val observabilityState: ObservabilityState,
    val actionabilityClass: ActionabilityClass,
    val evidence: List<EvidenceItem>,
    val humanExplanation: String
)

@JsonClass(generateAdapter = true)
data class DefensivePostureSummary(
    val packageName: String,
    val postureClass: DefensivePostureClass,
    val findingCount: Int,
    val highestSeverity: DefensiveFindingSeverity?,
    val findingIds: List<String>,
    val userFacingSummary: String
)
