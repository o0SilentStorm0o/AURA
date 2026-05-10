package cz.davidstrnadel.aura.storage

import android.content.Context
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.DefensiveSurfaceFinding
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.TemporalEpisode
import java.io.File

@JsonClass(generateAdapter = true)
data class SnapshotHistoryFile(
    val schemaVersion: Int,
    val writtenAt: Long,
    val snapshots: List<ObservedAppSnapshot>,
    val scanHistory: List<ScanHistoryEntry> = emptyList(),
    val packageHistory: List<PackageHistoryEntry> = emptyList()
)

@JsonClass(generateAdapter = true)
data class ScanHistoryEntry(
    val scanId: String,
    val collectedAt: Long,
    val packageCount: Int,
    val redCount: Int,
    val yellowCount: Int,
    val blueCount: Int,
    val grayCount: Int,
    val greenCount: Int,
    val temporalEpisodeCount: Int,
    val defensiveFindingCount: Int
)

@JsonClass(generateAdapter = true)
data class PackageHistoryEntry(
    val packageName: String,
    val firstObservedAt: Long,
    val lastObservedAt: Long,
    val scanCount: Int,
    val lastDecision: String,
    val lastRole: String,
    val lastProvenance: String
)

@JsonClass(generateAdapter = true)
data class ScanHistoryReport(
    val schemaVersion: Int,
    val retainedScanCount: Int,
    val retainedPackageCount: Int,
    val scans: List<ScanHistoryEntry>,
    val packagesChangedSincePreviousScan: List<String>,
    val packagesNewInThisScan: List<String>,
    val packagesRemovedSincePreviousScan: List<String>
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

    fun loadReport(): ScanHistoryReport =
        runCatching {
            if (!historyFile.exists()) return emptyReport()
            val history = adapter.fromJson(historyFile.readText()) ?: return emptyReport()
            if (history.schemaVersion != SCHEMA_VERSION) return emptyReport()
            history.toReport(
                changed = emptyList(),
                added = emptyList(),
                removed = emptyList()
            )
        }.getOrDefault(emptyReport())

    fun save(snapshots: List<ObservedAppSnapshot>, writtenAt: Long = System.currentTimeMillis()) {
        stateDir.mkdirs()
        val payload = SnapshotHistoryFile(
            schemaVersion = SCHEMA_VERSION,
            writtenAt = writtenAt,
            snapshots = snapshots.sortedBy { it.packageName }
        )
        writeAtomically(historyFile, adapter.indent("  ").toJson(payload))
    }

    fun appendScan(
        assessments: List<AuraAssessment>,
        temporalEpisodes: List<TemporalEpisode>,
        defensiveSurfaceFindings: List<DefensiveSurfaceFinding>,
        writtenAt: Long = System.currentTimeMillis()
    ): ScanHistoryReport {
        stateDir.mkdirs()
        val previous = runCatching {
            if (!historyFile.exists()) null else adapter.fromJson(historyFile.readText())
        }.getOrNull()
        val previousSnapshots = previous
            ?.takeIf { it.schemaVersion == SCHEMA_VERSION }
            ?.snapshots
            .orEmpty()
        val previousByPackage = previousSnapshots.associateBy { it.packageName }
        val snapshots = assessments.map { it.snapshot }.sortedBy { it.packageName }
        val currentByPackage = snapshots.associateBy { it.packageName }
        val changed = currentByPackage.values
            .filter { current ->
                val previousSnapshot = previousByPackage[current.packageName]
                previousSnapshot != null && previousSnapshot.fingerprint() != current.fingerprint()
            }
            .map { it.packageName }
            .sorted()
        val added = (currentByPackage.keys - previousByPackage.keys).sorted()
        val removed = (previousByPackage.keys - currentByPackage.keys).sorted()

        val scanCollectedAt = assessments.firstOrNull()?.snapshot?.collectedAt ?: writtenAt
        val scanEntry = assessments.toScanHistoryEntry(
            temporalEpisodeCount = temporalEpisodes.size,
            defensiveFindingCount = defensiveSurfaceFindings.size,
            collectedAt = scanCollectedAt
        )
        val packageHistory = mergePackageHistory(
            previous = previous?.packageHistory.orEmpty(),
            assessments = assessments,
            collectedAt = scanCollectedAt
        )
        val scanHistory = (previous?.scanHistory.orEmpty() + scanEntry)
            .takeLast(MAX_SCAN_HISTORY)
        val payload = SnapshotHistoryFile(
            schemaVersion = SCHEMA_VERSION,
            writtenAt = writtenAt,
            snapshots = snapshots,
            scanHistory = scanHistory,
            packageHistory = packageHistory
        )
        writeAtomically(historyFile, adapter.indent("  ").toJson(payload))
        return payload.toReport(
            changed = changed,
            added = added,
            removed = removed
        )
    }

    private fun List<AuraAssessment>.toScanHistoryEntry(
        temporalEpisodeCount: Int,
        defensiveFindingCount: Int,
        collectedAt: Long
    ): ScanHistoryEntry {
        val scanId = firstOrNull()?.snapshot?.scanId.orEmpty()
        return ScanHistoryEntry(
            scanId = scanId,
            collectedAt = collectedAt,
            packageCount = size,
            redCount = countColor(DecisionColor.RED),
            yellowCount = countColor(DecisionColor.YELLOW),
            blueCount = countColor(DecisionColor.BLUE),
            grayCount = countColor(DecisionColor.GRAY),
            greenCount = countColor(DecisionColor.GREEN),
            temporalEpisodeCount = temporalEpisodeCount,
            defensiveFindingCount = defensiveFindingCount
        )
    }

    private fun List<AuraAssessment>.countColor(color: DecisionColor): Int =
        count { it.decision.color == color }

    private fun mergePackageHistory(
        previous: List<PackageHistoryEntry>,
        assessments: List<AuraAssessment>,
        collectedAt: Long
    ): List<PackageHistoryEntry> {
        val previousByPackage = previous.associateBy { it.packageName }
        return assessments.map { assessment ->
            val packageName = assessment.snapshot.packageName
            val existing = previousByPackage[packageName]
            PackageHistoryEntry(
                packageName = packageName,
                firstObservedAt = existing?.firstObservedAt ?: collectedAt,
                lastObservedAt = collectedAt,
                scanCount = (existing?.scanCount ?: 0) + 1,
                lastDecision = assessment.decision.color.name,
                lastRole = assessment.role.predicted.name,
                lastProvenance = assessment.provenance.provenanceClass.name
            )
        }.sortedBy { it.packageName }
    }

    private fun SnapshotHistoryFile.toReport(
        changed: List<String>,
        added: List<String>,
        removed: List<String>
    ): ScanHistoryReport =
        ScanHistoryReport(
            schemaVersion = SCHEMA_VERSION,
            retainedScanCount = scanHistory.size,
            retainedPackageCount = packageHistory.size,
            scans = scanHistory,
            packagesChangedSincePreviousScan = changed,
            packagesNewInThisScan = added,
            packagesRemovedSincePreviousScan = removed
        )

    private fun ObservedAppSnapshot.fingerprint(): String =
        listOf(
            versionCode.toString(),
            lastUpdateTime.toString(),
            requestedPermissions.joinToString(","),
            grantedPermissions.joinToString(","),
            specialAccess.entries.sortedBy { it.key }.joinToString(",") { "${it.key}:${it.value}" },
            components.joinToString(",") { "${it.type}:${it.name}:${it.exported}:${it.permission}" }
        ).joinToString("|")

    private fun emptyReport(): ScanHistoryReport =
        ScanHistoryReport(
            schemaVersion = SCHEMA_VERSION,
            retainedScanCount = 0,
            retainedPackageCount = 0,
            scans = emptyList(),
            packagesChangedSincePreviousScan = emptyList(),
            packagesNewInThisScan = emptyList(),
            packagesRemovedSincePreviousScan = emptyList()
        )

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
        private const val MAX_SCAN_HISTORY = 20

        fun fromContext(context: Context): SnapshotHistoryStore =
            SnapshotHistoryStore(context.filesDir.resolve("state"))
    }
}
