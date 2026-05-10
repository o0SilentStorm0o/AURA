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

class ProvenanceClassifier {
    fun classify(snapshot: ObservedAppSnapshot): ProvenanceResult {
        val packageName = snapshot.packageName.lowercase()
        val installer = snapshot.installerPackageName.orEmpty().lowercase()
        val sourceDir = snapshot.sourceDir.lowercase()

        val result = when {
            packageName.startsWith("com.android.") && snapshot.isSystemApp ->
                Result(ProvenanceClass.AOSP_KNOWN, 0.82, "AOSP-style system package and system partition signal.")
            packageName.startsWith("com.google.") && snapshot.isSystemApp ->
                Result(ProvenanceClass.GOOGLE_KNOWN, 0.78, "Google package name with system-app provenance signal.")
            installer == "com.android.vending" ->
                Result(ProvenanceClass.PLAY_INSTALLED, 0.78, "Installer package is Google Play.")
            installer == "org.fdroid.fdroid" || installer.contains("fdroid") ->
                Result(ProvenanceClass.FDROID_OR_OPEN_SOURCE, 0.74, "Installer package indicates F-Droid/open-source distribution.")
            snapshot.isPrivilegedApp && (sourceDir.startsWith("/system/priv-app") || sourceDir.startsWith("/product/priv-app")) ->
                Result(ProvenanceClass.OPAQUE_PRIVILEGED, 0.62, "Privileged system location observed without transparency proof.")
            snapshot.isSystemApp ->
                Result(ProvenanceClass.OEM_SIGNED_SYSTEM, 0.58, "System app provenance observed, but exact vendor intent is opaque.")
            installer.isBlank() ->
                Result(ProvenanceClass.UNKNOWN_SIDELOAD, 0.66, "No installer package was observed for a non-system app.")
            else ->
                Result(ProvenanceClass.UNKNOWN, 0.42, "Installer/source signals do not map to a known provenance class.")
        }

        val evidence = EvidenceFactory.item(
            source = EvidenceSource.PROVENANCE_RULE,
            rawValue = "installer=${snapshot.installerPackageName};sourceDir=${snapshot.sourceDir}",
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
