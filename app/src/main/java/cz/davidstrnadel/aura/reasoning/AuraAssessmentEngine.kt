package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.ObservedAppSnapshot

class AuraAssessmentEngine(
    private val roleInferenceEngine: RoleInferenceEngine = RoleInferenceEngine(),
    private val provenanceClassifier: ProvenanceClassifier = ProvenanceClassifier(),
    private val riskDecisionEngine: RiskDecisionEngine = RiskDecisionEngine()
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

        return AuraAssessment(
            snapshot = snapshot,
            evidence = role.evidence + provenance.evidence + risk.evidence,
            role = role.role,
            provenance = provenance.provenance,
            riskVector = risk.riskVector,
            decision = risk.decision
        )
    }
}
