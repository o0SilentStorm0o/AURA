package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DefensiveFindingSeverity
import cz.davidstrnadel.aura.core.DefensivePostureClass
import cz.davidstrnadel.aura.core.DefensivePostureSummary
import cz.davidstrnadel.aura.core.DefensiveSurfaceFinding

class DefensivePostureAssessor {
    fun summarize(
        assessments: List<AuraAssessment>,
        findings: List<DefensiveSurfaceFinding>
    ): List<DefensivePostureSummary> {
        val findingsByPackage = findings.groupBy { it.packageName }
        return assessments.map { assessment ->
            val packageFindings = findingsByPackage[assessment.snapshot.packageName].orEmpty()
            val highestSeverity = packageFindings.maxByOrNull { it.severity.rank() }?.severity
            val postureClass = when {
                packageFindings.any { it.severity == DefensiveFindingSeverity.HIGH } || packageFindings.size >= 3 ->
                    DefensivePostureClass.WEAK_DEFENSIVE_SURFACE
                packageFindings.isNotEmpty() ->
                    DefensivePostureClass.REVIEW_RECOMMENDED
                else ->
                    DefensivePostureClass.NO_OBSERVED_WEAKNESS
            }
            DefensivePostureSummary(
                packageName = assessment.snapshot.packageName,
                postureClass = postureClass,
                findingCount = packageFindings.size,
                highestSeverity = highestSeverity,
                findingIds = packageFindings.map { it.findingId }.sorted(),
                userFacingSummary = summaryText(postureClass, packageFindings.size)
            )
        }.sortedBy { it.packageName }
    }

    private fun summaryText(postureClass: DefensivePostureClass, findingCount: Int): String =
        when (postureClass) {
            DefensivePostureClass.NO_OBSERVED_WEAKNESS ->
                "No defensive-surface weakness was observed by the current metadata-only audit."
            DefensivePostureClass.REVIEW_RECOMMENDED ->
                "AURA observed $findingCount defensive-surface finding(s). This is separate from the threat decision."
            DefensivePostureClass.WEAK_DEFENSIVE_SURFACE ->
                "AURA observed defensive-surface weaknesses. This does not automatically make the app malicious."
        }

    private fun DefensiveFindingSeverity.rank(): Int = when (this) {
        DefensiveFindingSeverity.INFO -> 0
        DefensiveFindingSeverity.LOW -> 1
        DefensiveFindingSeverity.MEDIUM -> 2
        DefensiveFindingSeverity.HIGH -> 3
    }
}
