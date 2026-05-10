package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.AuraDecision
import cz.davidstrnadel.aura.core.EvidenceGraph
import cz.davidstrnadel.aura.core.EvidenceGraphEdge
import cz.davidstrnadel.aura.core.EvidenceGraphNode
import cz.davidstrnadel.aura.core.EvidenceGraphNodeType
import cz.davidstrnadel.aura.core.EvidenceGraphRelation
import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ProvenanceAssessment
import cz.davidstrnadel.aura.core.RiskVector
import cz.davidstrnadel.aura.core.RoleInference
import java.util.Locale

class EvidenceGraphBuilder {
    fun build(
        snapshot: ObservedAppSnapshot,
        evidence: List<EvidenceItem>,
        role: RoleInference,
        provenance: ProvenanceAssessment,
        riskVector: RiskVector,
        decision: AuraDecision
    ): EvidenceGraph {
        val appNode = "app:${snapshot.packageName}"
        val roleNode = "role:${role.predicted.name}"
        val provenanceNode = "provenance:${provenance.provenanceClass.name}"
        val riskNode = "risk-vector:${snapshot.packageName}"
        val decisionNode = "decision:${decision.color.name}"
        val nodes = mutableListOf(
            EvidenceGraphNode(
                nodeId = appNode,
                type = EvidenceGraphNodeType.APP,
                label = snapshot.appLabel.ifBlank { snapshot.packageName },
                value = snapshot.packageName,
                confidence = 1.0
            ),
            EvidenceGraphNode(
                nodeId = roleNode,
                type = EvidenceGraphNodeType.ROLE,
                label = "Role ${role.predicted.name}",
                value = role.explanation,
                confidence = role.confidence
            ),
            EvidenceGraphNode(
                nodeId = provenanceNode,
                type = EvidenceGraphNodeType.PROVENANCE,
                label = "Provenance ${provenance.provenanceClass.name}",
                value = provenance.explanation,
                confidence = provenance.confidence
            ),
            EvidenceGraphNode(
                nodeId = riskNode,
                type = EvidenceGraphNodeType.RISK_VECTOR,
                label = "Risk vector",
                value = riskVector.toGraphValue(),
                confidence = 1.0
            ),
            EvidenceGraphNode(
                nodeId = decisionNode,
                type = EvidenceGraphNodeType.DECISION,
                label = "${decision.color.name} ${decision.title}",
                value = decision.explanation,
                confidence = 1.0
            )
        )
        val edges = mutableListOf<EvidenceGraphEdge>()

        evidence.forEach { item ->
            val evidenceNode = "evidence:${item.evidenceId}"
            nodes += EvidenceGraphNode(
                nodeId = evidenceNode,
                type = EvidenceGraphNodeType.EVIDENCE,
                label = item.source.name,
                value = item.normalizedValue,
                confidence = item.confidence
            )
            edges += EvidenceGraphEdge(
                from = evidenceNode,
                to = appNode,
                relation = EvidenceGraphRelation.OBSERVED_FOR,
                evidenceId = item.evidenceId
            )
            item.supports.mapNotNull { supportTarget(it, roleNode, provenanceNode, riskNode) }
                .forEach { target ->
                    edges += EvidenceGraphEdge(
                        from = evidenceNode,
                        to = target,
                        relation = EvidenceGraphRelation.SUPPORTS,
                        evidenceId = item.evidenceId
                    )
                }
            item.contradicts.mapNotNull { supportTarget(it, roleNode, provenanceNode, riskNode) }
                .forEach { target ->
                    edges += EvidenceGraphEdge(
                        from = evidenceNode,
                        to = target,
                        relation = EvidenceGraphRelation.CONTRADICTS,
                        evidenceId = item.evidenceId
                    )
                }
        }

        edges += EvidenceGraphEdge(roleNode, riskNode, EvidenceGraphRelation.DERIVES)
        edges += EvidenceGraphEdge(provenanceNode, riskNode, EvidenceGraphRelation.DERIVES)
        edges += EvidenceGraphEdge(riskNode, decisionNode, EvidenceGraphRelation.DERIVES)

        decision.recommendedActions.forEach { action ->
            val actionNode = "action:${action.actionId}"
            nodes += EvidenceGraphNode(
                nodeId = actionNode,
                type = EvidenceGraphNodeType.RECOMMENDED_ACTION,
                label = action.title,
                value = action.description,
                confidence = 1.0
            )
            edges += EvidenceGraphEdge(decisionNode, actionNode, EvidenceGraphRelation.RECOMMENDS)
        }

        return EvidenceGraph(
            nodes = nodes.distinctBy { it.nodeId },
            edges = edges.distinct()
        )
    }

    private fun supportTarget(
        support: String,
        roleNode: String,
        provenanceNode: String,
        riskNode: String
    ): String? = when {
        support.startsWith("role.") -> roleNode
        support.startsWith("provenance.") -> provenanceNode
        support == "risk.vector" -> riskNode
        else -> null
    }

    private fun RiskVector.toGraphValue(): String =
        String.format(
            Locale.US,
            "H=%.2f L=%.2f E=%.2f P=%.2f A=%.2f U=%.2f",
            harm,
            legitimacy,
            abuseEvidence,
            provenanceConfidence,
            actionability,
            uncertainty
        )
}
