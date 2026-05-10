package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.TemporalEpisode
import cz.davidstrnadel.aura.core.TemporalEpisodeType
import java.util.UUID

class TemporalEpisodeDetector {
    fun detect(previous: ObservedAppSnapshot?, current: ObservedAppSnapshot): List<TemporalEpisode> {
        val episodes = mutableListOf<TemporalEpisode>()
        val packageName = current.packageName
        val ageSinceInstall = current.collectedAt - current.firstInstallTime

        fun add(type: TemporalEpisodeType, ttlMillis: Long, explanation: String) {
            val evidence = EvidenceFactory.item(
                source = EvidenceSource.DECISION_POLICY,
                rawValue = type.name,
                normalizedValue = packageName,
                confidence = 0.78,
                observabilityState = ObservabilityState.OBSERVED_ENABLED,
                supports = listOf("temporal.${type.name.lowercase()}"),
                humanExplanation = explanation
            )
            episodes += TemporalEpisode(
                episodeId = UUID.nameUUIDFromBytes("${current.scanId}:$packageName:${type.name}".toByteArray()).toString(),
                scanId = current.scanId,
                packageName = packageName,
                type = type,
                startedAt = maxOf(current.firstInstallTime, previous?.collectedAt ?: current.firstInstallTime),
                detectedAt = current.collectedAt,
                ttlMillis = ttlMillis,
                evidenceIds = listOf(evidence.evidenceId),
                explanation = explanation
            )
        }

        if (previous != null &&
            previous.specialAccess["accessibility_service"] != ObservabilityState.OBSERVED_ENABLED &&
            current.specialAccess["accessibility_service"] == ObservabilityState.OBSERVED_ENABLED &&
            ageSinceInstall in 0..SIDELOAD_TO_ACCESSIBILITY_TTL
        ) {
            add(
                TemporalEpisodeType.SIDELOAD_TO_ACCESSIBILITY,
                SIDELOAD_TO_ACCESSIBILITY_TTL,
                "A newly installed app enabled Accessibility within the configured 30 minute window."
            )
        }

        if (previous != null &&
            previous.specialAccess["notification_listener"] != ObservabilityState.OBSERVED_ENABLED &&
            current.specialAccess["notification_listener"] == ObservabilityState.OBSERVED_ENABLED &&
            ageSinceInstall in 0..SIDELOAD_TO_NOTIFICATION_LISTENER_TTL
        ) {
            add(
                TemporalEpisodeType.SIDELOAD_TO_NOTIFICATION_LISTENER,
                SIDELOAD_TO_NOTIFICATION_LISTENER_TTL,
                "A newly installed app enabled notification listener access within the configured 30 minute window."
            )
        }

        if (current.specialAccess["overlay"] == ObservabilityState.OBSERVED_ENABLED &&
            current.rawFeatures["foregroundSensitiveAppRecentlyObserved"] == "true"
        ) {
            add(
                TemporalEpisodeType.SPECIAL_ACCESS_PLUS_SENSITIVE_APP,
                SPECIAL_ACCESS_PLUS_SENSITIVE_APP_TTL,
                "Overlay/special access was observed near a sensitive app foreground signal."
            )
        }

        if ((previous == null || previous.firstInstallTime != current.firstInstallTime) &&
            current.requestedPermissions.any { it.endsWith("RECEIVE_BOOT_COMPLETED") } &&
            ageSinceInstall in 0..BOOT_PERSISTENCE_AFTER_SIDELOAD_TTL
        ) {
            add(
                TemporalEpisodeType.BOOT_PERSISTENCE_AFTER_SIDELOAD,
                BOOT_PERSISTENCE_AFTER_SIDELOAD_TTL,
                "A newly installed app requested boot persistence within the configured 24 hour window."
            )
        }

        return episodes
    }

    companion object {
        const val SIDELOAD_TO_ACCESSIBILITY_TTL: Long = 30 * 60 * 1000L
        const val SIDELOAD_TO_NOTIFICATION_LISTENER_TTL: Long = 30 * 60 * 1000L
        const val SPECIAL_ACCESS_PLUS_SENSITIVE_APP_TTL: Long = 10 * 60 * 1000L
        const val BOOT_PERSISTENCE_AFTER_SIDELOAD_TTL: Long = 24 * 60 * 60 * 1000L
    }
}
