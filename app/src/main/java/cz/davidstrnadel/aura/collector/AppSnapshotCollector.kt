package cz.davidstrnadel.aura.collector

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
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

        return installedPackages().mapNotNull { packageInfo ->
            runCatching {
                packageInfo.toSnapshot(
                    scanId = scanId,
                    collectedAt = collectedAt,
                    enabledAccessibility = enabledAccessibility,
                    enabledNotificationListeners = enabledNotificationListeners
                )
            }.getOrNull()
        }.sortedBy { it.packageName }
    }

    private fun PackageInfo.toSnapshot(
        scanId: String,
        collectedAt: Long,
        enabledAccessibility: String,
        enabledNotificationListeners: String
    ): ObservedAppSnapshot {
        val appInfo = applicationInfo
        val requested = requestedPermissions?.toList().orEmpty().sorted()
        val granted = grantedPermissions().sorted()
        val components = observedComponents().sortedWith(compareBy({ it.type }, { it.name }))
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
            enabledNotificationListeners = enabledNotificationListeners
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
                "requestedPermissionCount" to requested.size.toString(),
                "grantedPermissionCount" to granted.size.toString(),
                "componentCount" to components.size.toString(),
                "hasBootPersistence" to requested.any { it.endsWith("RECEIVE_BOOT_COMPLETED") }.toString(),
                "foregroundSensitiveAppRecentlyObserved" to "false"
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

    private fun PackageInfo.observedComponents(): List<ObservedComponent> {
        val output = mutableListOf<ObservedComponent>()
        activities?.forEach {
            output += ObservedComponent(it.name, "activity", it.exported, it.permission)
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
        enabledNotificationListeners: String
    ): Map<String, ObservabilityState> {
        val declaresAccessibility = components.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" }
        val declaresNotificationListener = components.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" }
        val requestsOverlay = requestedPermissions.any { it == "android.permission.SYSTEM_ALERT_WINDOW" }
        val requestsInstallPackages = requestedPermissions.any { it == "android.permission.REQUEST_INSTALL_PACKAGES" }

        return mapOf(
            "accessibility_service" to when {
                declaresAccessibility && enabledAccessibility.contains(packageName) -> ObservabilityState.OBSERVED_ENABLED
                declaresAccessibility -> ObservabilityState.OBSERVED_DISABLED
                else -> ObservabilityState.OBSERVED_DISABLED
            },
            "notification_listener" to when {
                declaresNotificationListener && enabledNotificationListeners.contains(packageName) -> ObservabilityState.OBSERVED_ENABLED
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
            },
            "usage_stats" to ObservabilityState.USER_GRANT_REQUIRED
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

    companion object {
        private const val FLAG_PRIVILEGED_COMPAT = 1 shl 30
    }
}
