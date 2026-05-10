package cz.davidstrnadel.aura.collector

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import cz.davidstrnadel.aura.BuildConfig
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservedComponent
import cz.davidstrnadel.aura.core.ObservabilityState
import java.security.MessageDigest
import java.util.UUID

class AppSnapshotCollector(private val context: Context) {
    private val packageManager: PackageManager = context.packageManager

    fun collect(scanId: String = UUID.randomUUID().toString()): List<ObservedAppSnapshot> {
        val collectedAt = System.currentTimeMillis()
        val enabledAccessibility = secureSetting("enabled_accessibility_services")
        val enabledNotificationListeners = secureSetting("enabled_notification_listeners")
        val enabledNotificationListenerPackages = runCatching {
            NotificationManagerCompat.getEnabledListenerPackages(context)
        }.getOrDefault(emptySet())
        val packageInfos = installedPackages()
        val foregroundSensitiveSignal = foregroundSensitiveSignal(collectedAt, packageInfos)

        return packageInfos.mapNotNull { packageInfo ->
            runCatching {
                packageInfo.toSnapshot(
                    scanId = scanId,
                    collectedAt = collectedAt,
                    enabledAccessibility = enabledAccessibility,
                    enabledNotificationListeners = enabledNotificationListeners,
                    enabledNotificationListenerPackages = enabledNotificationListenerPackages,
                    foregroundSensitiveSignal = foregroundSensitiveSignal
                )
            }.getOrNull()
        }.sortedBy { it.packageName }
    }

    private fun PackageInfo.toSnapshot(
        scanId: String,
        collectedAt: Long,
        enabledAccessibility: String,
        enabledNotificationListeners: String,
        enabledNotificationListenerPackages: Set<String>,
        foregroundSensitiveSignal: ForegroundSensitiveSignal
    ): ObservedAppSnapshot {
        val appInfo = applicationInfo
        val requested = requestedPermissions?.toList().orEmpty().sorted()
        val granted = grantedPermissions().sorted()
        val components = observedComponents(launcherActivityNames(packageName)).sortedWith(compareBy({ it.type }, { it.name }))
        val installer = installerPackage(packageName)
        val signing = signingDigests()
        val sourceDir = appInfo?.sourceDir.orEmpty()
        val appFlags = appInfo?.flags ?: 0
        val isSystem = appFlags.and(ApplicationInfo.FLAG_SYSTEM) != 0
        val isUpdatedSystem = appFlags.and(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        val isPrivileged = appFlags.and(FLAG_PRIVILEGED_COMPAT) != 0 || sourceDir.contains("/priv-app/")
        val specialAccess = specialAccessStates(
            packageName = packageName,
            uid = appInfo?.uid ?: -1,
            requestedPermissions = requested,
            components = components,
            enabledAccessibility = enabledAccessibility,
            enabledNotificationListeners = enabledNotificationListeners,
            enabledNotificationListenerPackages = enabledNotificationListenerPackages
        )

        return ObservedAppSnapshot(
            snapshotId = UUID.nameUUIDFromBytes("$scanId:$packageName:$collectedAt".toByteArray()).toString(),
            scanId = scanId,
            collectedAt = collectedAt,
            apiLevel = Build.VERSION.SDK_INT,
            androidVersion = Build.VERSION.RELEASE.orEmpty(),
            securityPatchLevel = if (Build.VERSION.SDK_INT >= 23) Build.VERSION.SECURITY_PATCH.orEmpty() else "unknown",
            collectorVersion = BuildConfig.COLLECTOR_VERSION,
            flavor = "${BuildConfig.AURA_DISTRIBUTION_FLAVOR}/${BuildConfig.AURA_CAPABILITY_FLAVOR}",
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
            packageName = packageName,
            appLabel = appInfo?.loadLabel(packageManager)?.toString().orEmpty(),
            versionName = versionName,
            versionCode = versionCodeCompat(),
            uid = appInfo?.uid ?: -1,
            firstInstallTime = firstInstallTime,
            lastUpdateTime = lastUpdateTime,
            installerPackageName = installer,
            sourceDir = sourceDir,
            isSystemApp = isSystem,
            isPrivilegedApp = isPrivileged,
            isUpdatedSystemApp = isUpdatedSystem,
            requestedPermissions = requested,
            grantedPermissions = granted,
            signingCertDigestsSha256 = signing,
            components = components,
            specialAccess = specialAccess,
            rawFeatures = mapOf(
                "distributionFlavor" to BuildConfig.AURA_DISTRIBUTION_FLAVOR,
                "capabilityFlavor" to BuildConfig.AURA_CAPABILITY_FLAVOR,
                "fullInventory" to BuildConfig.AURA_FULL_INVENTORY.toString(),
                "sourcePartition" to sourcePartition(sourceDir),
                "usageStatsObservability" to foregroundSensitiveSignal.observabilityState.name,
                "usageStatsLookbackMillis" to USAGE_STATS_LOOKBACK_MILLIS.toString(),
                "requestedPermissionCount" to requested.size.toString(),
                "grantedPermissionCount" to granted.size.toString(),
                "componentCount" to components.size.toString(),
                "exportedComponentCount" to components.count { it.exported }.toString(),
                "unprotectedExportedComponentCount" to unprotectedExportedComponents(components).size.toString(),
                "allowBackup" to appFlags.and(ApplicationInfo.FLAG_ALLOW_BACKUP).let { (it != 0).toString() },
                "debuggable" to appFlags.and(ApplicationInfo.FLAG_DEBUGGABLE).let { (it != 0).toString() },
                "usesCleartextTraffic" to appFlags.and(ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC).let { (it != 0).toString() },
                "networkSecurityConfigObservability" to ObservabilityState.DECLARED_ONLY.name,
                "hasBootPersistence" to requested.any { it.endsWith("RECEIVE_BOOT_COMPLETED") }.toString(),
                "foregroundSensitiveAppRecentlyObserved" to (foregroundSensitiveSignal.packageName != null).toString(),
                "foregroundSensitiveAppPackage" to foregroundSensitiveSignal.packageName.orEmpty(),
                "foregroundSensitiveAppAgeMillis" to foregroundSensitiveSignal.ageMillis?.toString().orEmpty()
            )
        )
    }

    @Suppress("DEPRECATION")
    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            PackageManager.GET_SIGNATURES or
            PackageManager.GET_SIGNING_CERTIFICATES
        return if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            packageManager.getInstalledPackages(flags)
        }
    }

    private fun PackageInfo.versionCodeCompat(): Long =
        if (Build.VERSION.SDK_INT >= 28) longVersionCode else @Suppress("DEPRECATION") versionCode.toLong()

    private fun PackageInfo.grantedPermissions(): List<String> {
        val permissions = requestedPermissions ?: return emptyList()
        val flags = requestedPermissionsFlags ?: return emptyList()
        return permissions.filterIndexed { index, _ ->
            flags.getOrNull(index)?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }
    }

    private fun PackageInfo.observedComponents(launcherActivityNames: Set<String>): List<ObservedComponent> {
        val output = mutableListOf<ObservedComponent>()
        activities?.forEach {
            output += ObservedComponent(
                name = it.name,
                type = "activity",
                exported = it.exported,
                permission = it.permission,
                isLauncherEntryPoint = it.name in launcherActivityNames
            )
        }
        services?.forEach {
            output += ObservedComponent(it.name, "service", it.exported, it.permission)
        }
        receivers?.forEach {
            output += ObservedComponent(it.name, "receiver", it.exported, it.permission)
        }
        providers?.forEach {
            output += ObservedComponent(it.name, "provider", it.exported, it.readPermission ?: it.writePermission)
        }
        return output
    }

    @Suppress("DEPRECATION")
    private fun launcherActivityNames(packageName: String): Set<String> {
        val intent = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(packageName)
        val resolved = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0L))
        } else {
            packageManager.queryIntentActivities(intent, 0)
        }
        return resolved.mapNotNull { it.activityInfo?.name }.toSet()
    }

    private fun unprotectedExportedComponents(components: List<ObservedComponent>): List<ObservedComponent> =
        components.filter { component ->
            component.exported &&
                component.permission.isNullOrBlank() &&
                !component.isLauncherEntryPoint
        }

    @Suppress("DEPRECATION")
    private fun PackageInfo.signingDigests(): List<String> {
        val signatures = if (Build.VERSION.SDK_INT >= 28) {
            signingInfo?.apkContentsSigners?.toList().orEmpty()
        } else {
            signatures?.toList().orEmpty()
        }
        return signatures.map { sha256(it.toByteArray()) }.distinct().sorted()
    }

    private fun installerPackage(packageName: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }
    }.getOrNull()

    private fun specialAccessStates(
        packageName: String,
        uid: Int,
        requestedPermissions: List<String>,
        components: List<ObservedComponent>,
        enabledAccessibility: String,
        enabledNotificationListeners: String,
        enabledNotificationListenerPackages: Set<String>
    ): Map<String, ObservabilityState> {
        val declaresAccessibility = components.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" }
        val declaresNotificationListener = components.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" }
        val requestsOverlay = requestedPermissions.any { it == "android.permission.SYSTEM_ALERT_WINDOW" }
        val requestsInstallPackages = requestedPermissions.any { it == "android.permission.REQUEST_INSTALL_PACKAGES" }

        return mapOf(
            "accessibility_service" to when {
                declaresAccessibility && settingContainsPackage(enabledAccessibility, packageName) -> ObservabilityState.OBSERVED_ENABLED
                declaresAccessibility -> ObservabilityState.OBSERVED_DISABLED
                else -> ObservabilityState.OBSERVED_DISABLED
            },
            "notification_listener" to when {
                declaresNotificationListener && (
                    settingContainsPackage(enabledNotificationListeners, packageName) ||
                        packageName in enabledNotificationListenerPackages
                    ) -> ObservabilityState.OBSERVED_ENABLED
                declaresNotificationListener -> ObservabilityState.OBSERVED_DISABLED
                else -> ObservabilityState.OBSERVED_DISABLED
            },
            "overlay" to when {
                requestsOverlay -> overlayState(uid, packageName)
                else -> ObservabilityState.OBSERVED_DISABLED
            },
            "request_install_packages" to when {
                requestsInstallPackages -> ObservabilityState.DECLARED_ONLY
                else -> ObservabilityState.OBSERVED_DISABLED
            }
        )
    }

    private fun overlayState(uid: Int, packageName: String): ObservabilityState {
        if (uid < 0) return ObservabilityState.UNKNOWN_API_LIMITATION
        return runCatching {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= 29) {
                appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, uid, packageName)
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, uid, packageName)
            }
            if (mode == AppOpsManager.MODE_ALLOWED) {
                ObservabilityState.OBSERVED_ENABLED
            } else {
                ObservabilityState.OBSERVED_DISABLED
            }
        }.getOrElse {
            ObservabilityState.UNKNOWN_API_LIMITATION
        }
    }

    private fun secureSetting(name: String): String =
        runCatching { Settings.Secure.getString(context.contentResolver, name).orEmpty() }.getOrDefault("")

    private fun foregroundSensitiveSignal(
        collectedAt: Long,
        packageInfos: List<PackageInfo>
    ): ForegroundSensitiveSignal {
        val observability = usageStatsObservability()
        if (observability != ObservabilityState.OBSERVED_ENABLED) {
            return ForegroundSensitiveSignal(observability)
        }

        val sensitivePackages = packageInfos
            .filter { it.looksSensitive() }
            .map { it.packageName }
            .toSet()
        if (sensitivePackages.isEmpty()) {
            return ForegroundSensitiveSignal(ObservabilityState.OBSERVED_ENABLED)
        }

        return runCatching {
            val usageStats = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val events = usageStats.queryEvents(collectedAt - USAGE_STATS_LOOKBACK_MILLIS, collectedAt)
            val event = UsageEvents.Event()
            var latestPackage: String? = null
            var latestTimestamp = 0L

            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.packageName in sensitivePackages &&
                    event.isForegroundEvent() &&
                    event.timeStamp >= latestTimestamp
                ) {
                    latestPackage = event.packageName
                    latestTimestamp = event.timeStamp
                }
            }

            ForegroundSensitiveSignal(
                observabilityState = ObservabilityState.OBSERVED_ENABLED,
                packageName = latestPackage,
                ageMillis = latestPackage?.let { collectedAt - latestTimestamp }
            )
        }.getOrElse {
            ForegroundSensitiveSignal(ObservabilityState.UNKNOWN_API_LIMITATION)
        }
    }

    private fun PackageInfo.looksSensitive(): Boolean {
        val packageName = this.packageName.lowercase()
        val label = applicationInfo?.loadLabel(packageManager)?.toString().orEmpty().lowercase()
        return SENSITIVE_FOREGROUND_MARKERS.any { marker ->
            marker in packageName || marker in label
        }
    }

    @Suppress("DEPRECATION")
    private fun UsageEvents.Event.isForegroundEvent(): Boolean =
        eventType == UsageEvents.Event.MOVE_TO_FOREGROUND ||
            (Build.VERSION.SDK_INT >= 29 && eventType == UsageEvents.Event.ACTIVITY_RESUMED)

    private fun usageStatsObservability(): ObservabilityState {
        if (!BuildConfig.AURA_FULL_INVENTORY) {
            return ObservabilityState.REQUIRES_RESEARCH_FLAVOR
        }
        return runCatching {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= 29) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName
                )
            }
            if (mode == AppOpsManager.MODE_ALLOWED) {
                ObservabilityState.OBSERVED_ENABLED
            } else {
                ObservabilityState.USER_GRANT_REQUIRED
            }
        }.getOrElse {
            ObservabilityState.UNKNOWN_API_LIMITATION
        }
    }

    private fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun sourcePartition(sourceDir: String): String = when {
        sourceDir.startsWith("/system/priv-app") -> "system_priv_app"
        sourceDir.startsWith("/system/app") -> "system_app"
        sourceDir.startsWith("/product/priv-app") -> "product_priv_app"
        sourceDir.startsWith("/product/app") -> "product_app"
        sourceDir.startsWith("/vendor/priv-app") -> "vendor_priv_app"
        sourceDir.startsWith("/vendor/app") -> "vendor_app"
        sourceDir.startsWith("/data/app") -> "data_app"
        else -> "unknown"
    }

    private fun settingContainsPackage(setting: String, packageName: String): Boolean =
        setting.split(':').any { entry ->
            val componentPackage = entry.substringBefore('/')
            componentPackage == packageName
        }

    companion object {
        private const val FLAG_PRIVILEGED_COMPAT = 1 shl 30
        private const val USAGE_STATS_LOOKBACK_MILLIS = 10 * 60 * 1000L
        private val SENSITIVE_FOREGROUND_MARKERS = setOf(
            "bank",
            "pay",
            "wallet",
            "password",
            "authenticator",
            "health",
            "eid"
        )
    }

    private data class ForegroundSensitiveSignal(
        val observabilityState: ObservabilityState,
        val packageName: String? = null,
        val ageMillis: Long? = null
    )
}
