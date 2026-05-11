package cz.davidstrnadel.aura.reasoning

import android.content.Context
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import cz.davidstrnadel.aura.core.RoleCategory

@JsonClass(generateAdapter = true)
data class RoleRuleAsset(
    val role: String,
    val confidence: Double = 0.60,
    val permissions: List<String> = emptyList(),
    val packageOrLabelMarkers: List<String> = emptyList(),
    val componentMarkers: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class RoleRulesAsset(
    val schemaVersion: Int,
    val rules: List<RoleRuleAsset>
)

@JsonClass(generateAdapter = true)
data class PermissionHarmAsset(
    val schemaVersion: Int,
    val permissions: Map<String, Double>
)

@JsonClass(generateAdapter = true)
data class KnownPackagesAsset(
    val schemaVersion: Int,
    val packages: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class KnownPatternsAsset(
    val schemaVersion: Int,
    val patterns: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class KnownSignaturesAsset(
    val schemaVersion: Int,
    val sha256Digests: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class ProvenanceRuleAsset(
    @Json(name = "class")
    val provenanceClass: String,
    val signal: String
)

@JsonClass(generateAdapter = true)
data class ProvenanceRulesAsset(
    val schemaVersion: Int,
    val rules: List<ProvenanceRuleAsset> = emptyList()
)

@JsonClass(generateAdapter = true)
data class DecisionPolicyAsset(
    val schemaVersion: Int,
    val policyVersion: String = "0.1.0",
    val policy: Map<String, String>
)

class AuraRuleAssets(
    val roleRules: List<RoleRuleAsset> = DEFAULT_ROLE_RULES,
    val permissionHarm: Map<String, Double> = DEFAULT_PERMISSION_HARM,
    val knownAospPackages: Set<String> = DEFAULT_AOSP_PACKAGES,
    val knownGooglePackages: Set<String> = DEFAULT_GOOGLE_PACKAGES,
    val knownOemPatterns: List<String> = DEFAULT_OEM_PATTERNS,
    val knownFdroidSignatures: Set<String> = emptySet(),
    val provenanceRules: List<ProvenanceRuleAsset> = DEFAULT_PROVENANCE_RULES,
    val decisionPolicyVersion: String = DEFAULT_DECISION_POLICY_VERSION,
    val decisionPolicy: Map<String, String> = DEFAULT_DECISION_POLICY
) {
    fun roleRulesFor(role: RoleCategory): List<RoleRuleAsset> =
        roleRules.filter { it.role == role.name }

    companion object {
        const val DEFAULT_DECISION_POLICY_VERSION = "0.1.0"

        val DEFAULT_PERMISSION_HARM = mapOf(
            "android.permission.CAMERA" to 0.68,
            "android.permission.RECORD_AUDIO" to 0.76,
            "android.permission.ACCESS_FINE_LOCATION" to 0.72,
            "android.permission.ACCESS_COARSE_LOCATION" to 0.52,
            "android.permission.READ_SMS" to 0.82,
            "android.permission.SEND_SMS" to 0.88,
            "android.permission.RECEIVE_SMS" to 0.74,
            "android.permission.READ_CONTACTS" to 0.64,
            "android.permission.READ_CALL_LOG" to 0.76,
            "android.permission.CALL_PHONE" to 0.68,
            "android.permission.READ_PHONE_STATE" to 0.62,
            "android.permission.REQUEST_INSTALL_PACKAGES" to 0.70,
            "android.permission.RECEIVE_BOOT_COMPLETED" to 0.45,
            "android.permission.SYSTEM_ALERT_WINDOW" to 0.78,
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to 0.90,
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to 0.82
        )

        val DEFAULT_ROLE_RULES = listOf(
            RoleRuleAsset(
                role = RoleCategory.CAMERA.name,
                confidence = 0.86,
                permissions = listOf("android.permission.CAMERA"),
                packageOrLabelMarkers = listOf("camera")
            ),
            RoleRuleAsset(
                role = RoleCategory.MAPS_NAVIGATION.name,
                confidence = 0.82,
                permissions = listOf("android.permission.ACCESS_FINE_LOCATION"),
                packageOrLabelMarkers = listOf("map", "maps", "navigation", "nav")
            ),
            RoleRuleAsset(
                role = RoleCategory.ACCESSIBILITY_TOOL.name,
                confidence = 0.78,
                componentMarkers = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
                packageOrLabelMarkers = listOf("accessibility", "screenreader", "screen reader", "talkback", "assistive", "reader")
            ),
            RoleRuleAsset(
                role = RoleCategory.KEYBOARD.name,
                confidence = 0.82,
                componentMarkers = listOf("android.view.InputMethod", "bind_input_method")
            ),
            RoleRuleAsset(
                role = RoleCategory.VPN_SECURITY_APP.name,
                confidence = 0.72,
                componentMarkers = listOf("vpnservice"),
                packageOrLabelMarkers = listOf("vpn", "security")
            ),
            RoleRuleAsset(
                role = RoleCategory.PAYMENT_BANKING.name,
                confidence = 0.72,
                packageOrLabelMarkers = listOf("bank", "pay", "wallet")
            )
        )

        val DEFAULT_AOSP_PACKAGES = setOf(
            "android",
            "com.android.camera",
            "com.android.contacts",
            "com.android.dialer",
            "com.android.launcher3",
            "com.android.packageinstaller",
            "com.android.providers.media",
            "com.android.settings",
            "com.android.systemui"
        )

        val DEFAULT_GOOGLE_PACKAGES = setOf(
            "com.android.chrome",
            "com.google.android.apps.maps",
            "com.google.android.apps.messaging",
            "com.google.android.apps.photos",
            "com.google.android.gms",
            "com.google.android.googlequicksearchbox",
            "com.google.android.inputmethod.latin",
            "com.google.android.webview"
        )

        val DEFAULT_OEM_PATTERNS = listOf(
            "com.samsung.",
            "com.miui.",
            "com.xiaomi.",
            "com.huawei.",
            "com.oppo.",
            "com.vivo.",
            "com.motorola.",
            "com.sonyericsson.",
            "com.oneplus."
        )

        val DEFAULT_DECISION_POLICY = mapOf(
            "RED" to "high harm + high abuse evidence + low role legitimacy + active risky capability + high user actionability",
            "BLUE" to "platform/OEM/security research audit finding; never primary panic queue",
            "GRAY" to "insufficient evidence or high uncertainty without abuse evidence",
            "GREEN" to "expected for role with sufficient provenance trust and low abuse evidence",
            "YELLOW" to "review recommended, not panic"
        )

        val DEFAULT_PROVENANCE_RULES = listOf(
            ProvenanceRuleAsset("PLAY_INSTALLED", "installerPackageName == com.android.vending"),
            ProvenanceRuleAsset("FDROID_OR_OPEN_SOURCE", "installerPackageName contains fdroid"),
            ProvenanceRuleAsset("OPAQUE_PRIVILEGED", "priv-app source path without transparency evidence"),
            ProvenanceRuleAsset("UNKNOWN_SIDELOAD", "non-system app with no installer package")
        )

        fun fromContext(context: Context): AuraRuleAssets {
            val moshi = Moshi.Builder()
                .add(KotlinJsonAdapterFactory())
                .build()

            fun readAsset(name: String): String? =
                runCatching {
                    context.assets.open("aura/$name").bufferedReader().use { it.readText() }
                }.getOrNull()

            fun <T> readJson(name: String, type: Class<T>): T? =
                readAsset(name)?.let { json ->
                    runCatching { moshi.adapter(type).fromJson(json) }.getOrNull()
                }

            val decisionPolicyAsset = readJson("decision_policy.json", DecisionPolicyAsset::class.java)
            return AuraRuleAssets(
                roleRules = readJson("role_rules.json", RoleRulesAsset::class.java)?.rules ?: DEFAULT_ROLE_RULES,
                permissionHarm = readJson("permission_harm_model.json", PermissionHarmAsset::class.java)?.permissions ?: DEFAULT_PERMISSION_HARM,
                knownAospPackages = readJson("known_aosp_packages.json", KnownPackagesAsset::class.java)?.packages?.toSet() ?: DEFAULT_AOSP_PACKAGES,
                knownGooglePackages = readJson("known_google_packages.json", KnownPackagesAsset::class.java)?.packages?.toSet() ?: DEFAULT_GOOGLE_PACKAGES,
                knownOemPatterns = readJson("known_oem_patterns.json", KnownPatternsAsset::class.java)?.patterns ?: DEFAULT_OEM_PATTERNS,
                knownFdroidSignatures = readJson("known_fdroid_signatures.json", KnownSignaturesAsset::class.java)?.sha256Digests?.toSet().orEmpty(),
                provenanceRules = readJson("provenance_rules.json", ProvenanceRulesAsset::class.java)?.rules ?: DEFAULT_PROVENANCE_RULES,
                decisionPolicyVersion = decisionPolicyAsset?.policyVersion ?: DEFAULT_DECISION_POLICY_VERSION,
                decisionPolicy = decisionPolicyAsset?.policy ?: DEFAULT_DECISION_POLICY
            )
        }
    }
}
