package cz.davidstrnadel.aura.core

import com.squareup.moshi.JsonClass

enum class TemporalEpisodeType {
    SIDELOAD_TO_ACCESSIBILITY,
    SIDELOAD_TO_NOTIFICATION_LISTENER,
    SPECIAL_ACCESS_PLUS_SENSITIVE_APP,
    BOOT_PERSISTENCE_AFTER_SIDELOAD
}

@JsonClass(generateAdapter = true)
data class TemporalEpisode(
    val episodeId: String,
    val scanId: String,
    val packageName: String,
    val type: TemporalEpisodeType,
    val startedAt: Long,
    val detectedAt: Long,
    val ttlMillis: Long,
    val evidenceIds: List<String>,
    val explanation: String
)
