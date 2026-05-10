package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.TemporalEpisodeType
import org.junit.Assert.assertEquals
import org.junit.Test

class TemporalEpisodeDetectorTest {
    private val detector = TemporalEpisodeDetector()

    @Test
    fun detectsAccessibilityEnableWithinThirtyMinutes() {
        val previous = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            specialAccess = TestSnapshots.defaultSpecialAccess()
        ).let { it.copy(collectedAt = it.firstInstallTime - 1000L) }
        val current = previous.copy(
            collectedAt = previous.firstInstallTime + 10 * 60 * 1000L,
            specialAccess = previous.specialAccess + (
                "accessibility_service" to ObservabilityState.OBSERVED_ENABLED
                )
        )

        val episodes = detector.detect(previous, current)

        assertEquals(TemporalEpisodeType.SIDELOAD_TO_ACCESSIBILITY, episodes.single().type)
    }

    @Test
    fun ignoresAccessibilityEnableOutsideThirtyMinutes() {
        val previous = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            specialAccess = TestSnapshots.defaultSpecialAccess()
        ).let { it.copy(collectedAt = it.firstInstallTime - 1000L) }
        val current = previous.copy(
            collectedAt = previous.firstInstallTime + 31 * 60 * 1000L,
            specialAccess = previous.specialAccess + (
                "accessibility_service" to ObservabilityState.OBSERVED_ENABLED
                )
        )

        val episodes = detector.detect(previous, current)

        assertEquals(0, episodes.size)
    }
}
