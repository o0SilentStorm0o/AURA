package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.PrivacyImpact
import java.util.Locale

object EvidenceFactory {
    fun item(
        source: EvidenceSource,
        rawValue: String,
        normalizedValue: String,
        confidence: Double,
        observabilityState: ObservabilityState,
        supports: List<String>,
        contradicts: List<String> = emptyList(),
        humanExplanation: String,
        privacyImpact: PrivacyImpact = PrivacyImpact.APP_METADATA
    ): EvidenceItem {
        val stableKey = listOf(source.name, normalizedValue, supports.joinToString("|"))
            .joinToString(":")
            .lowercase(Locale.US)
            .replace(Regex("[^a-z0-9]+"), "_")
            .trim('_')
        return EvidenceItem(
            evidenceId = "ev_$stableKey",
            source = source,
            rawValue = rawValue,
            normalizedValue = normalizedValue,
            confidence = confidence.coerceIn(0.0, 1.0),
            observabilityState = observabilityState,
            privacyImpact = privacyImpact,
            supports = supports,
            contradicts = contradicts,
            humanExplanation = humanExplanation
        )
    }
}
