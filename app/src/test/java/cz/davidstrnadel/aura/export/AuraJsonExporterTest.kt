package cz.davidstrnadel.aura.export

import cz.davidstrnadel.aura.reasoning.AuraAssessmentEngine
import cz.davidstrnadel.aura.reasoning.DefensiveSurfaceAuditor
import cz.davidstrnadel.aura.reasoning.TestSnapshots
import cz.davidstrnadel.aura.storage.ScanHistoryReport
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
        val defensiveFindings = DefensiveSurfaceAuditor().audit(listOf(assessment))
        val export = AuraScanExport(
            schemaVersion = 1,
            scanId = "scan",
            generatedAt = 1L,
            flavor = "researchFull/standard",
            assessments = listOf(assessment),
            temporalEpisodes = emptyList(),
            defensiveSurfaceFindings = defensiveFindings,
            scanHistory = ScanHistoryReport(
                schemaVersion = 1,
                retainedScanCount = 1,
                retainedPackageCount = 1,
                scans = emptyList(),
                packagesChangedSincePreviousScan = emptyList(),
                packagesNewInThisScan = listOf("com.android.camera"),
                packagesRemovedSincePreviousScan = emptyList()
            )
        )

        val json = AuraJsonExporter().toJson(export)

        assertTrue(json.contains("\"schemaVersion\": 1"))
        assertTrue(json.contains("\"observabilityState\""))
        assertTrue(json.contains("\"riskVector\""))
        assertTrue(json.contains("\"decision\""))
        assertTrue(json.contains("\"recommendedActions\""))
        assertTrue(json.contains("\"evidenceGraph\""))
        assertTrue(json.contains("\"edges\""))
        assertTrue(json.contains("\"defensiveSurfaceFindings\""))
        assertTrue(json.contains("\"scanHistory\""))
        assertTrue(json.contains("\"packagesNewInThisScan\""))
    }
}
