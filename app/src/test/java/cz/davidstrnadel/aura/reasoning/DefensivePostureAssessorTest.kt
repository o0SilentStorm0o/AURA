package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.DefensivePostureClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DefensivePostureAssessorTest {
    @Test
    fun threatDecisionStaysSeparateFromWeakDefensivePosture() {
        val assessment = AuraAssessmentEngine().assess(
            TestSnapshots.app(
                packageName = "com.example.leakybank",
                appLabel = "Fixture Bank Debug",
                rawFeatures = TestSnapshots.defaultRawFeatures() + mapOf(
                    "allowBackup" to "true",
                    "debuggable" to "true",
                    "usesCleartextTraffic" to "true"
                )
            )
        )
        val findings = DefensiveSurfaceAuditor().audit(listOf(assessment))

        val postures = DefensivePostureAssessor().summarize(listOf(assessment), findings)

        assertEquals(1, postures.size)
        assertEquals(DefensivePostureClass.WEAK_DEFENSIVE_SURFACE, postures.single().postureClass)
        assertTrue(postures.single().userFacingSummary.contains("does not automatically"))
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun noFindingsProduceNoObservedWeaknessPosture() {
        val assessment = AuraAssessmentEngine().assess(
            TestSnapshots.app(
                packageName = "com.example.sensitivebank",
                appLabel = "Fixture Bank"
            )
        )

        val postures = DefensivePostureAssessor().summarize(listOf(assessment), emptyList())

        assertEquals(DefensivePostureClass.NO_OBSERVED_WEAKNESS, postures.single().postureClass)
        assertEquals(0, postures.single().findingCount)
    }
}
