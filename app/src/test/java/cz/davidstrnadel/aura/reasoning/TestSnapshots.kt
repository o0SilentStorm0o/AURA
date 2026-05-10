package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservedComponent
import cz.davidstrnadel.aura.core.ObservabilityState

object TestSnapshots {
    fun app(
        packageName: String,
        appLabel: String = packageName,
        installerPackageName: String? = "com.android.vending",
        sourceDir: String = "/data/app/$packageName/base.apk",
        isSystemApp: Boolean = false,
        isPrivilegedApp: Boolean = false,
        requestedPermissions: List<String> = emptyList(),
        grantedPermissions: List<String> = emptyList(),
        components: List<ObservedComponent> = emptyList(),
        specialAccess: Map<String, ObservabilityState> = defaultSpecialAccess()
    ): ObservedAppSnapshot = ObservedAppSnapshot(
        snapshotId = "snapshot-$packageName",
        scanId = "scan",
        collectedAt = 1_710_000_000_000L,
        apiLevel = 35,
        androidVersion = "15",
        securityPatchLevel = "2026-05-01",
        collectorVersion = "test",
        flavor = "researchFull/standard",
        deviceModel = "fixture",
        packageName = packageName,
        appLabel = appLabel,
        versionName = "1",
        versionCode = 1,
        uid = 12345,
        firstInstallTime = 1_709_999_000_000L,
        lastUpdateTime = 1_709_999_000_000L,
        installerPackageName = installerPackageName,
        sourceDir = sourceDir,
        isSystemApp = isSystemApp,
        isPrivilegedApp = isPrivilegedApp,
        isUpdatedSystemApp = false,
        requestedPermissions = requestedPermissions,
        grantedPermissions = grantedPermissions,
        signingCertDigestsSha256 = listOf("fixture"),
        components = components,
        specialAccess = specialAccess,
        rawFeatures = mapOf(
            "sourcePartition" to if (sourceDir.startsWith("/data/app")) "data_app" else "system_priv_app",
            "foregroundSensitiveAppRecentlyObserved" to "false"
        )
    )

    fun defaultSpecialAccess(): Map<String, ObservabilityState> = mapOf(
        "accessibility_service" to ObservabilityState.OBSERVED_DISABLED,
        "notification_listener" to ObservabilityState.OBSERVED_DISABLED,
        "overlay" to ObservabilityState.OBSERVED_DISABLED,
        "request_install_packages" to ObservabilityState.OBSERVED_DISABLED,
        "usage_stats" to ObservabilityState.USER_GRANT_REQUIRED
    )
}
