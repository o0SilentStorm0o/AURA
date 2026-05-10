package cz.davidstrnadel.aura.storage

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
}
