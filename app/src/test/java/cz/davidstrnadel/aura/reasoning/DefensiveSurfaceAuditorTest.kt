package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.DefensiveFindingType
import cz.davidstrnadel.aura.core.ObservedComponent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DefensiveSurfaceAuditorTest {
    private val assessmentEngine = AuraAssessmentEngine()
    private val auditor = DefensiveSurfaceAuditor()

    @Test
    fun sensitiveDebugBackupCleartextAppProducesDefensiveFindings() {
        val assessment = assessmentEngine.assess(
            TestSnapshots.app(
                packageName = "com.example.leakybank",
                appLabel = "Fixture Bank Debug",
                rawFeatures = TestSnapshots.defaultRawFeatures() + mapOf(
                    "debuggable" to "true",
                    "allowBackup" to "true",
                    "usesCleartextTraffic" to "true"
                )
            )
        )

        val findings = auditor.audit(listOf(assessment))

        assertEquals(
            setOf(
                DefensiveFindingType.DEBUGGABLE_SENSITIVE_APP,
                DefensiveFindingType.BACKUP_ALLOWED_SENSITIVE_APP,
                DefensiveFindingType.CLEARTEXT_TRAFFIC_ALLOWED
            ),
            findings.map { it.findingType }.toSet()
        )
        assertTrue(findings.all { it.packageName == "com.example.leakybank" })
    }

    @Test
    fun launcherActivityIsNotTreatedAsUnprotectedExportedSurface() {
        val assessment = assessmentEngine.assess(
            TestSnapshots.app(
                packageName = "com.example.bank",
                appLabel = "Fixture Bank",
                components = listOf(
                    ObservedComponent(
                        name = "com.example.bank.MainActivity",
                        type = "activity",
                        exported = true,
                        permission = null,
                        isLauncherEntryPoint = true
                    )
                )
            )
        )

        val findings = auditor.audit(listOf(assessment))

        assertFalse(findings.any { it.findingType == DefensiveFindingType.UNPROTECTED_EXPORTED_COMPONENT })
    }

    @Test
    fun exportedNonLauncherComponentProducesDefensiveFinding() {
        val assessment = assessmentEngine.assess(
            TestSnapshots.app(
                packageName = "com.example.bank",
                appLabel = "Fixture Bank",
                components = listOf(
                    ObservedComponent(
                        name = "com.example.bank.SyncService",
                        type = "service",
                        exported = true,
                        permission = null
                    )
                )
            )
        )

        val findings = auditor.audit(listOf(assessment))

        assertEquals(
            DefensiveFindingType.UNPROTECTED_EXPORTED_COMPONENT,
            findings.single().findingType
        )
    }
}
