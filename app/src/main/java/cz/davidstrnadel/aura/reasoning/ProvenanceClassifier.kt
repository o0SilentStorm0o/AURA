package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.EvidenceSource
import cz.davidstrnadel.aura.core.ObservedAppSnapshot
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.ProvenanceAssessment
import cz.davidstrnadel.aura.core.ProvenanceClass

data class ProvenanceResult(
    val provenance: ProvenanceAssessment,
    val evidence: List<EvidenceItem>
)

class ProvenanceClassifier(
    private val assets: AuraRuleAssets = AuraRuleAssets()
) {
    fun classify(snapshot: ObservedAppSnapshot): ProvenanceResult {
        val packageName = snapshot.packageName.lowercase()
        val installer = snapshot.installerPackageName.orEmpty().lowercase()
        val sourceDir = snapshot.sourceDir.lowercase()
        val signingDigests = snapshot.signingCertDigestsSha256.map { it.lowercase() }.toSet()
        val knownAospPackages = assets.knownAospPackages.map { it.lowercase() }.toSet()
        val knownGooglePackages = assets.knownGooglePackages.map { it.lowercase() }.toSet()
        val knownFdroidSignatures = assets.knownFdroidSignatures.map { it.lowercase() }.toSet()

        val result = when {
            (packageName in knownAospPackages || packageName.startsWith("android.auto_generated_rro_")) && snapshot.isSystemApp ->
                Result(ProvenanceClass.AOSP_KNOWN, 0.86, "Known AOSP package identity with system partition evidence.")
            packageName.startsWith("com.android.") && snapshot.isSystemApp ->
                Result(ProvenanceClass.AOSP_KNOWN, 0.82, "AOSP-style system package and system partition signal.")
            packageName in knownGooglePackages && snapshot.isSystemApp ->
                Result(ProvenanceClass.GOOGLE_KNOWN, 0.82, "Known Google package identity with system-app provenance evidence.")
            packageName.startsWith("com.google.") && snapshot.isSystemApp ->
                Result(ProvenanceClass.GOOGLE_KNOWN, 0.78, "Google package name with system-app provenance signal.")
            installer == "com.android.vending" ->
                Result(ProvenanceClass.PLAY_INSTALLED, 0.78, "Installer package is Google Play.")
            installer == "org.fdroid.fdroid" || installer.contains("fdroid") || signingDigests.any { it in knownFdroidSignatures } ->
                Result(ProvenanceClass.FDROID_OR_OPEN_SOURCE, 0.74, "Installer or signing digest indicates F-Droid/open-source distribution.")
            installer == "com.android.shell" ->
                Result(ProvenanceClass.UNKNOWN_SIDELOAD, 0.70, "App was installed through adb/shell in a lab or sideload context.")
            snapshot.isPrivilegedApp && (sourceDir.startsWith("/system/priv-app") || sourceDir.startsWith("/product/priv-app")) ->
                Result(ProvenanceClass.OPAQUE_PRIVILEGED, 0.62, "Privileged system location observed without transparency proof.")
            snapshot.isSystemApp && assets.knownOemPatterns.any { packageName.startsWith(it.lowercase()) } ->
                Result(ProvenanceClass.OEM_SIGNED_SYSTEM, 0.64, "Known OEM package-name pattern with system-app provenance evidence.")
            snapshot.isSystemApp ->
                Result(ProvenanceClass.OEM_SIGNED_SYSTEM, 0.58, "System app provenance observed, but exact vendor intent is opaque.")
            installer.isBlank() ->
                Result(ProvenanceClass.UNKNOWN_SIDELOAD, 0.66, "No installer package was observed for a non-system app.")
            else ->
                Result(ProvenanceClass.UNKNOWN, 0.42, "Installer/source signals do not map to a known provenance class.")
        }

        val policySignal = assets.provenanceRules
            .firstOrNull { it.provenanceClass == result.provenanceClass.name }
            ?.signal
            ?: "classifier fallback"
        val evidence = EvidenceFactory.item(
            source = EvidenceSource.PROVENANCE_RULE,
            rawValue = "installer=${snapshot.installerPackageName};sourceDir=${snapshot.sourceDir};signingDigests=${snapshot.signingCertDigestsSha256.joinToString(",")};policySignal=$policySignal",
            normalizedValue = result.provenanceClass.name,
            confidence = result.confidence,
            observabilityState = ObservabilityState.OBSERVED_ENABLED,
            supports = listOf("provenance.${result.provenanceClass.name.lowercase()}"),
            humanExplanation = result.explanation
        )

        return ProvenanceResult(
            provenance = ProvenanceAssessment(
                provenanceClass = result.provenanceClass,
                confidence = result.confidence,
                evidenceIds = listOf(evidence.evidenceId),
                explanation = result.explanation
            ),
            evidence = listOf(evidence)
        )
    }

    private data class Result(
        val provenanceClass: ProvenanceClass,
        val confidence: Double,
        val explanation: String
    )
}
