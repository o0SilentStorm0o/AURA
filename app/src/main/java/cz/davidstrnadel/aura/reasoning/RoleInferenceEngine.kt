package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.RoleCategory
import cz.davidstrnadel.aura.core.RoleInference

data class RoleInferenceResult(
    val role: RoleInference,
    val evidence: List<EvidenceItem>
)

class RoleInferenceEngine(
    private val assets: AuraRuleAssets = AuraRuleAssets()
) {
    fun infer(snapshot: ObservedAppSnapshot): RoleInferenceResult {
        val packageName = snapshot.packageName.lowercase()
        val label = snapshot.appLabel.lowercase()
        val permissions = snapshot.requestedPermissions.map { it.substringAfterLast('.') }.toSet()
        val componentNames = snapshot.components.joinToString(" ") {
            "${it.name} ${it.type} ${it.permission.orEmpty()}"
        }.lowercase()

        val candidates = mutableListOf<Candidate>()

        fun addCandidate(role: RoleCategory, confidence: Double, reason: String, raw: String) {
            candidates += Candidate(role, confidence, reason, raw)
        }

        assets.roleRules.forEach { rule ->
            val role = runCatching { RoleCategory.valueOf(rule.role) }.getOrNull() ?: return@forEach
            val permissionMatch = rule.permissions.isEmpty() ||
                rule.permissions.any { expected ->
                    expected in snapshot.requestedPermissions || expected.substringAfterLast('.') in permissions
                }
            val markerMatch = rule.packageOrLabelMarkers.isEmpty() ||
                rule.packageOrLabelMarkers.any { it.lowercase() in packageName || it.lowercase() in label }
            val componentMatch = rule.componentMarkers.isEmpty() ||
                rule.componentMarkers.any { it.lowercase() in componentNames }
            if (permissionMatch && markerMatch && componentMatch) {
                addCandidate(
                    role,
                    rule.confidence,
                    "Asset role rule matched ${rule.role}.",
                    "asset-role-rule:${rule.role}"
                )
            }
        }

        if (packageName == "android" || packageName.startsWith("android.auto_generated_rro_")) {
            addCandidate(
                RoleCategory.SYSTEM_COMPONENT,
                0.84,
                "Framework/RRO package is treated as a platform component, not a user-facing accessibility tool.",
                "platform-framework-or-rro"
            )
        }
        if (snapshot.isSystemApp && packageName.startsWith("com.android.providers.media")) {
            addCandidate(RoleCategory.MEDIA_PROVIDER, 0.84, "AOSP media provider package signal.", "media-provider")
        }
        if (snapshot.isSystemApp && packageName.startsWith("com.android.providers.contacts")) {
            addCandidate(RoleCategory.CONTACTS_PROVIDER, 0.84, "AOSP contacts provider package signal.", "contacts-provider")
        }
        if (snapshot.isSystemApp && packageName.startsWith("com.android.providers.")) {
            addCandidate(RoleCategory.SYSTEM_COMPONENT, 0.80, "AOSP provider package is treated as a platform component.", "android-provider")
        }

        if ("CAMERA" in permissions || "camera" in packageName || "camera" in label) {
            addCandidate(RoleCategory.CAMERA, 0.86, "Camera capability and naming match a camera role.", "camera-signals")
        }
        if ("ACCESS_FINE_LOCATION" in permissions && listOf("map", "maps", "navigation", "nav").any { it in packageName || it in label }) {
            addCandidate(RoleCategory.MAPS_NAVIGATION, 0.82, "Location capability fits a maps/navigation role.", "maps-signals")
        }
        val declaresAccessibilityService =
            "android.permission.BIND_ACCESSIBILITY_SERVICE".lowercase() in componentNames &&
                packageName != "android" &&
                !packageName.startsWith("android.auto_generated_rro_")
        val looksAssistive = listOf(
            "accessibility",
            "screenreader",
            "screen reader",
            "talkback",
            "assistive",
            "reader"
        ).any { it in packageName || it in label }
        if (declaresAccessibilityService && looksAssistive) {
            addCandidate(
                RoleCategory.ACCESSIBILITY_TOOL,
                0.78,
                "Manifest declares an Accessibility service and package/label signals an assistive tool.",
                "accessibility-service-assistive"
            )
        }
        if ("android.view.InputMethod".lowercase() in componentNames || "bind_input_method" in componentNames) {
            addCandidate(RoleCategory.KEYBOARD, 0.82, "Manifest declares an input method service.", "input-method")
        }
        if ("vpnservice" in componentNames || "vpn" in packageName || "vpn" in label) {
            addCandidate(RoleCategory.VPN_SECURITY_APP, 0.72, "VPN/security naming or service signals are present.", "vpn-security")
        }
        if (listOf("browser", "chrome", "webview").any { it in packageName || it in label }) {
            addCandidate(RoleCategory.BROWSER, 0.76, "Browser/WebView naming signals are present.", "browser-signals")
        }
        if (!packageName.startsWith("com.android.providers.") &&
            (listOf("dialer", "phone").any { it in packageName || it in label } || "CALL_PHONE" in permissions)
        ) {
            addCandidate(RoleCategory.DIALER, 0.72, "Dialer/phone permission or naming signals are present.", "dialer-signals")
        }
        if (listOf("bank", "pay", "wallet").any { it in packageName || it in label }) {
            addCandidate(RoleCategory.PAYMENT_BANKING, 0.72, "Payment/banking naming signals are present.", "payment-signals")
        }
        if (snapshot.isSystemApp && listOf("telemetry", "analytics", "stats", "metrics").any { it in packageName || it in label }) {
            addCandidate(RoleCategory.OEM_TELEMETRY_SERVICE, 0.68, "System app has telemetry or metrics naming signals.", "telemetry-signals")
        }
        if (snapshot.isSystemApp && candidates.isEmpty()) {
            addCandidate(RoleCategory.SYSTEM_COMPONENT, 0.58, "System app without a stronger user-facing role signal.", "system-component")
        }

        val best = candidates.maxByOrNull { it.confidence }
            ?: if (snapshot.installerPackageName == null && !snapshot.isSystemApp) {
                Candidate(RoleCategory.UNKNOWN_SIDELOAD, 0.62, "No trusted installer or role signal was observed.", "unknown-sideload")
            } else {
                Candidate(RoleCategory.UNKNOWN_UTILITY, 0.46, "No strong role signal was observed.", "unknown-utility")
            }

        val evidence = EvidenceFactory.item(
            source = EvidenceSource.ROLE_RULE,
            rawValue = best.raw,
            normalizedValue = best.role.name,
            confidence = best.confidence,
            observabilityState = ObservabilityState.OBSERVED_ENABLED,
            supports = listOf("role.${best.role.name.lowercase()}"),
            humanExplanation = best.reason
        )

        return RoleInferenceResult(
            role = RoleInference(
                predicted = best.role,
                confidence = best.confidence,
                evidenceIds = listOf(evidence.evidenceId),
                explanation = best.reason
            ),
            evidence = listOf(evidence)
        )
    }

    private data class Candidate(
        val role: RoleCategory,
        val confidence: Double,
        val reason: String,
        val raw: String
    )
}
