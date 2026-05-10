package cz.davidstrnadel.aura.storage

import android.content.Context
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import java.io.File

@JsonClass(generateAdapter = true)
data class SnapshotHistoryFile(
    val schemaVersion: Int,
    val writtenAt: Long,
    val snapshots: List<ObservedAppSnapshot>
)

class SnapshotHistoryStore(private val stateDir: File) {
    private val moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
    private val adapter = moshi.adapter(SnapshotHistoryFile::class.java)
    private val historyFile: File = stateDir.resolve("previous-snapshots.json")

    fun loadByPackage(): Map<String, ObservedAppSnapshot> =
        runCatching {
            if (!historyFile.exists()) return emptyMap()
            val history = adapter.fromJson(historyFile.readText()) ?: return emptyMap()
            if (history.schemaVersion != SCHEMA_VERSION) return emptyMap()
            history.snapshots.associateBy { it.packageName }
        }.getOrDefault(emptyMap())

    fun save(snapshots: List<ObservedAppSnapshot>, writtenAt: Long = System.currentTimeMillis()) {
        stateDir.mkdirs()
        val payload = SnapshotHistoryFile(
            schemaVersion = SCHEMA_VERSION,
            writtenAt = writtenAt,
            snapshots = snapshots.sortedBy { it.packageName }
        )
        writeAtomically(historyFile, adapter.indent("  ").toJson(payload))
    }

    private fun writeAtomically(file: File, content: String) {
        val tempFile = file.resolveSibling("${file.name}.tmp")
        tempFile.writeText(content)
        if (!tempFile.renameTo(file)) {
            file.writeText(content)
            tempFile.delete()
        }
    }

    companion object {
        const val SCHEMA_VERSION = 1

        fun fromContext(context: Context): SnapshotHistoryStore =
            SnapshotHistoryStore(context.filesDir.resolve("state"))
    }
}
