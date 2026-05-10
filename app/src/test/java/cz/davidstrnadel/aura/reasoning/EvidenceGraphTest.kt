package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.EvidenceGraphNodeType
import cz.davidstrnadel.aura.core.EvidenceGraphRelation
import cz.davidstrnadel.aura.core.ObservabilityState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceGraphTest {
    @Test
    fun graphLinksEvidenceToRiskDecisionAndActions() {
        val assessment = AuraAssessmentEngine().assess(
            TestSnapshots.app(
                packageName = "com.flashlight.cleaner.update",
                appLabel = "Security Update",
                installerPackageName = null,
                requestedPermissions = listOf(
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                    "android.permission.SYSTEM_ALERT_WINDOW"
                ),
                specialAccess = TestSnapshots.defaultSpecialAccess() + mapOf(
                    "accessibility_service" to ObservabilityState.OBSERVED_ENABLED,
                    "notification_listener" to ObservabilityState.OBSERVED_ENABLED,
                    "overlay" to ObservabilityState.OBSERVED_ENABLED
                )
            )
        )

        val graph = assessment.evidenceGraph
        val nodeTypes = graph.nodes.map { it.type }.toSet()

        assertEquals(DecisionColor.RED, assessment.decision.color)
        assertTrue(EvidenceGraphNodeType.APP in nodeTypes)
        assertTrue(EvidenceGraphNodeType.EVIDENCE in nodeTypes)
        assertTrue(EvidenceGraphNodeType.RISK_VECTOR in nodeTypes)
        assertTrue(EvidenceGraphNodeType.DECISION in nodeTypes)
        assertTrue(EvidenceGraphNodeType.RECOMMENDED_ACTION in nodeTypes)
        assertTrue(
            graph.edges.any {
                it.from.startsWith("risk-vector:") &&
                    it.to == "decision:RED" &&
                    it.relation == EvidenceGraphRelation.DERIVES
            }
        )
        assertTrue(
            graph.edges.any {
                it.from == "decision:RED" &&
                    it.to == "action:disable_risky_special_access" &&
                    it.relation == EvidenceGraphRelation.RECOMMENDS
            }
        )
        assertTrue(graph.edges.any { it.relation == EvidenceGraphRelation.SUPPORTS })
    }
}
