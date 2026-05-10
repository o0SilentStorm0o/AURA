package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.ObservedAppSnapshot

class AuraAssessmentEngine(
    private val roleInferenceEngine: RoleInferenceEngine = RoleInferenceEngine(),
    private val provenanceClassifier: ProvenanceClassifier = ProvenanceClassifier(),
    private val riskDecisionEngine: RiskDecisionEngine = RiskDecisionEngine(),
    private val evidenceGraphBuilder: EvidenceGraphBuilder = EvidenceGraphBuilder()
) {
    fun assess(snapshot: ObservedAppSnapshot): AuraAssessment {
        val role = roleInferenceEngine.infer(snapshot)
        val provenance = provenanceClassifier.classify(snapshot)
        val risk = riskDecisionEngine.decide(
            snapshot = snapshot,
            role = role.role.predicted,
            roleConfidence = role.role.confidence,
            provenanceClass = provenance.provenance.provenanceClass,
            provenanceConfidence = provenance.provenance.confidence
        )

        val evidence = role.evidence + provenance.evidence + risk.evidence
        val evidenceGraph = evidenceGraphBuilder.build(
            snapshot = snapshot,
            evidence = evidence,
            role = role.role,
            provenance = provenance.provenance,
            riskVector = risk.riskVector,
            decision = risk.decision
        )

        return AuraAssessment(
            snapshot = snapshot,
            evidence = evidence,
            role = role.role,
            provenance = provenance.provenance,
            riskVector = risk.riskVector,
            decision = risk.decision,
            decisionTrace = risk.decisionTrace,
            userRiskStory = risk.userRiskStory,
            evidenceGraph = evidenceGraph
        )
    }

    companion object {
        fun fromAssets(assets: AuraRuleAssets): AuraAssessmentEngine =
            AuraAssessmentEngine(
                roleInferenceEngine = RoleInferenceEngine(assets),
                provenanceClassifier = ProvenanceClassifier(assets),
                riskDecisionEngine = RiskDecisionEngine(assets)
            )
    }
}
