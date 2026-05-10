package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.ProvenanceClass
import cz.davidstrnadel.aura.core.RoleCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AssetDrivenRulesTest {
    @Test
    fun roleInferenceUsesExternalRoleRulesBeforeFallbackHeuristics() {
        val engine = RoleInferenceEngine(
            AuraRuleAssets(
                roleRules = listOf(
                    RoleRuleAsset(
                        role = RoleCategory.VPN_SECURITY_APP.name,
                        confidence = 0.91,
                        packageOrLabelMarkers = listOf("scopeguard")
                    )
                )
            )
        )

        val result = engine.infer(
            TestSnapshots.app(
                packageName = "com.example.scopeguard",
                appLabel = "ScopeGuard"
            )
        )

        assertEquals(RoleCategory.VPN_SECURITY_APP, result.role.predicted)
        assertEquals(0.91, result.role.confidence, 0.001)
        assertTrue(result.evidence.single().rawValue.contains("asset-role-rule"))
    }

    @Test
    fun provenanceClassifierUsesKnownPackageAssetsAsEvidenceNotWhitelist() {
        val classifier = ProvenanceClassifier(
            AuraRuleAssets(
                knownGooglePackages = setOf("com.example.googlecomponent")
            )
        )

        val result = classifier.classify(
            TestSnapshots.app(
                packageName = "com.example.googlecomponent",
                appLabel = "Google Component",
                installerPackageName = null,
                sourceDir = "/system/app/GoogleComponent/GoogleComponent.apk",
                isSystemApp = true
            )
        )

        assertEquals(ProvenanceClass.GOOGLE_KNOWN, result.provenance.provenanceClass)
        assertTrue(result.provenance.explanation.contains("Known Google package"))
    }

    @Test
    fun customPermissionHarmAssetInfluencesDecisionWithoutParallelDetector() {
        val engine = AuraAssessmentEngine(
            roleInferenceEngine = RoleInferenceEngine(),
            provenanceClassifier = ProvenanceClassifier(),
            riskDecisionEngine = RiskDecisionEngine(
                AuraRuleAssets(
                    permissionHarm = mapOf("android.permission.POST_NOTIFICATIONS" to 0.91)
                )
            )
        )

        val assessment = engine.assess(
            TestSnapshots.app(
                packageName = "com.example.notifier",
                appLabel = "Notifier",
                requestedPermissions = listOf("android.permission.POST_NOTIFICATIONS"),
                grantedPermissions = listOf("android.permission.POST_NOTIFICATIONS")
            )
        )

        assertTrue(assessment.riskVector.harm >= 0.90)
        assertEquals(DecisionColor.YELLOW, assessment.decision.color)
    }
}
