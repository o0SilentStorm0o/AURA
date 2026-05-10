package cz.davidstrnadel.aura.storage

import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.reasoning.AuraAssessmentEngine
import cz.davidstrnadel.aura.reasoning.TestSnapshots
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class SnapshotHistoryStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun savesAndLoadsSnapshotsByPackage() {
        val stateDir = temporaryFolder.newFolder("state")
        val store = SnapshotHistoryStore(stateDir)
        val camera = TestSnapshots.app("com.android.camera")
        val utility = TestSnapshots.app("com.example.utility")

        store.save(listOf(utility, camera), writtenAt = 1L)

        val loaded = store.loadByPackage()
        assertEquals(setOf("com.android.camera", "com.example.utility"), loaded.keys)
        assertEquals(camera.packageName, loaded.getValue("com.android.camera").packageName)
    }

    @Test
    fun corruptHistoryFailsClosedToEmptyMap() {
        val stateDir = temporaryFolder.newFolder("state")
        stateDir.resolve("previous-snapshots.json").writeText("{not-json")

        val loaded = SnapshotHistoryStore(stateDir).loadByPackage()

        assertTrue(loaded.isEmpty())
    }

    @Test
    fun appendScanTracksScanAndPackageHistoryDiffs() {
        val stateDir = temporaryFolder.newFolder("state")
        val store = SnapshotHistoryStore(stateDir)
        val assessmentEngine = AuraAssessmentEngine()
        val camera = assessmentEngine.assess(
            TestSnapshots.app(
                packageName = "com.android.camera",
                appLabel = "Camera",
                installerPackageName = null,
                sourceDir = "/system/priv-app/Camera/Camera.apk",
                isSystemApp = true,
                isPrivilegedApp = true,
                requestedPermissions = listOf("android.permission.CAMERA")
            )
        )
        val utility = assessmentEngine.assess(TestSnapshots.app("com.example.utility"))

        val firstReport = store.appendScan(
            assessments = listOf(camera, utility),
            temporalEpisodes = emptyList(),
            defensiveSurfaceFindings = emptyList(),
            writtenAt = 10L
        )

        val changedUtility = assessmentEngine.assess(
            TestSnapshots.app(
                packageName = "com.example.utility",
                specialAccess = TestSnapshots.defaultSpecialAccess() + mapOf(
                    "overlay" to ObservabilityState.OBSERVED_ENABLED
                )
            )
        )
        val newUnknown = assessmentEngine.assess(TestSnapshots.app("com.example.newapp", installerPackageName = null))
        val secondReport = store.appendScan(
            assessments = listOf(changedUtility, newUnknown),
            temporalEpisodes = emptyList(),
            defensiveSurfaceFindings = emptyList(),
            writtenAt = 20L
        )

        assertEquals(1, firstReport.retainedScanCount)
        assertEquals(listOf("com.android.camera", "com.example.utility"), firstReport.packagesNewInThisScan)
        assertEquals(2, secondReport.retainedScanCount)
        assertEquals(listOf("com.example.utility"), secondReport.packagesChangedSincePreviousScan)
        assertEquals(listOf("com.example.newapp"), secondReport.packagesNewInThisScan)
        assertEquals(listOf("com.android.camera"), secondReport.packagesRemovedSincePreviousScan)
        assertTrue(secondReport.scans.any { it.grayCount >= 1 || it.yellowCount >= 1 })
        assertEquals(2, store.loadReport().retainedPackageCount)
        assertTrue(store.loadReport().packagesChangedSincePreviousScan.isEmpty())
    }
}
