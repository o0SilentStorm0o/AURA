package cz.davidstrnadel.aura.export

import cz.davidstrnadel.aura.reasoning.AuraAssessmentEngine
import cz.davidstrnadel.aura.reasoning.TestSnapshots
import org.junit.Assert.assertTrue
import org.junit.Test

class AuraJsonExporterTest {
    @Test
    fun exportContainsStableSchemaAndEvidenceShape() {
        val assessment = AuraAssessmentEngine().assess(
            TestSnapshots.app(
                packageName = "com.android.camera",
                appLabel = "Camera",
                sourceDir = "/system/priv-app/Camera/Camera.apk",
                isSystemApp = true,
                isPrivilegedApp = true,
                requestedPermissions = listOf("android.permission.CAMERA")
            )
        )
        val export = AuraScanExport(
            schemaVersion = 1,
            scanId = "scan",
            generatedAt = 1L,
            flavor = "researchFull/standard",
            assessments = listOf(assessment),
            temporalEpisodes = emptyList()
        )

        val json = AuraJsonExporter().toJson(export)

        assertTrue(json.contains("\"schemaVersion\": 1"))
        assertTrue(json.contains("\"observabilityState\""))
        assertTrue(json.contains("\"riskVector\""))
        assertTrue(json.contains("\"decision\""))
    }
}
