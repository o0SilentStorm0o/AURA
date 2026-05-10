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
    fun detectsAccessibilityEnableAfterBaselineScanWithinThirtyMinutes() {
        val previous = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            specialAccess = TestSnapshots.defaultSpecialAccess()
        ).let {
            it.copy(
                firstInstallTime = it.collectedAt - 5 * 60 * 1000L,
                collectedAt = it.collectedAt
            )
        }
        val current = previous.copy(
            collectedAt = previous.collectedAt + 5 * 60 * 1000L,
            specialAccess = previous.specialAccess + (
                "accessibility_service" to ObservabilityState.OBSERVED_ENABLED
                )
        )

        val episodes = detector.detect(previous, current)

        assertEquals(TemporalEpisodeType.SIDELOAD_TO_ACCESSIBILITY, episodes.single().type)
    }

    @Test
    fun detectsAccessibilityAndNotificationListenerInSameScan() {
        val previous = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            specialAccess = TestSnapshots.defaultSpecialAccess()
        ).let {
            it.copy(firstInstallTime = it.collectedAt - 5 * 60 * 1000L)
        }
        val current = previous.copy(
            collectedAt = previous.collectedAt + 5 * 60 * 1000L,
            specialAccess = previous.specialAccess + mapOf(
                "accessibility_service" to ObservabilityState.OBSERVED_ENABLED,
                "notification_listener" to ObservabilityState.OBSERVED_ENABLED
            )
        )

        val episodes = detector.detect(previous, current)

        assertEquals(
            listOf(
                TemporalEpisodeType.SIDELOAD_TO_ACCESSIBILITY,
                TemporalEpisodeType.SIDELOAD_TO_NOTIFICATION_LISTENER
            ),
            episodes.map { it.type }
        )
    }

    @Test
    fun detectsBootPersistenceForNewlyObservedInstall() {
        val current = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            requestedPermissions = listOf("android.permission.RECEIVE_BOOT_COMPLETED")
        ).let {
            it.copy(firstInstallTime = it.collectedAt - 10 * 60 * 1000L)
        }

        val episodes = detector.detect(null, current)

        assertEquals(TemporalEpisodeType.BOOT_PERSISTENCE_AFTER_SIDELOAD, episodes.single().type)
    }

    @Test
    fun detectsOverlayNearSensitiveForegroundSignal() {
        val current = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            specialAccess = TestSnapshots.defaultSpecialAccess() + (
                "overlay" to ObservabilityState.OBSERVED_ENABLED
                ),
            rawFeatures = TestSnapshots.defaultRawFeatures() + mapOf(
                "foregroundSensitiveAppRecentlyObserved" to "true",
                "foregroundSensitiveAppPackage" to "com.example.sensitivebank",
                "foregroundSensitiveAppAgeMillis" to (5 * 60 * 1000L).toString()
            )
        )

        val episodes = detector.detect(previous = null, current = current)

        assertEquals(
            listOf(
                TemporalEpisodeType.SPECIAL_ACCESS_PLUS_SENSITIVE_APP
            ),
            episodes.map { it.type }
        )
    }

    @Test
    fun ignoresOverlayWhenSensitiveForegroundSignalIsOutsideWindow() {
        val current = TestSnapshots.app(
            packageName = "com.example.side",
            installerPackageName = null,
            specialAccess = TestSnapshots.defaultSpecialAccess() + (
                "overlay" to ObservabilityState.OBSERVED_ENABLED
                ),
            rawFeatures = TestSnapshots.defaultRawFeatures() + mapOf(
                "foregroundSensitiveAppRecentlyObserved" to "true",
                "foregroundSensitiveAppPackage" to "com.example.sensitivebank",
                "foregroundSensitiveAppAgeMillis" to (11 * 60 * 1000L).toString()
            )
        )

        val episodes = detector.detect(previous = null, current = current)

        assertEquals(0, episodes.size)
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
