package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ActionabilityClass
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.ObservedComponent
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.RemediationScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DecisionPolicyTest {
    private val engine = AuraAssessmentEngine()

    @Test
    fun systemCameraIsExpectedRoleNotPanicAlert() {
        val snapshot = TestSnapshots.app(
            packageName = "com.android.camera",
            appLabel = "Camera",
            installerPackageName = null,
            sourceDir = "/system/priv-app/Camera/Camera.apk",
            isSystemApp = true,
            isPrivilegedApp = true,
            requestedPermissions = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO"
            ),
            grantedPermissions = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO"
            )
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.GREEN, assessment.decision.color)
        assertFalse(assessment.decision.userAlert)
        assertEquals(DecisionColor.GREEN, assessment.decisionTrace.selectedDecision)
        assertTrue(assessment.userRiskStory.headline.isNotBlank())
    }

    @Test
    fun opaqueSystemTelemetryBecomesBlueAuditFinding() {
        val snapshot = TestSnapshots.app(
            packageName = "com.vendor.telemetry",
            appLabel = "OEM Telemetry",
            installerPackageName = null,
            sourceDir = "/vendor/priv-app/Telemetry/Telemetry.apk",
            isSystemApp = true,
            isPrivilegedApp = true,
            requestedPermissions = listOf(
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE"
            ),
            grantedPermissions = listOf(
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE"
            )
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.BLUE, assessment.decision.color)
        assertFalse(assessment.decision.userAlert)
        assertTrue(assessment.decision.expertFinding)
        assertTrue(assessment.decision.recommendedActions.none { it.userFacing })
        assertTrue(assessment.decision.recommendedActions.any { it.scope == RemediationScope.EXPERT_AUDIT })
        assertTrue(assessment.decision.recommendedActions.any { it.actionId == "audit_platform_component" })
        assertTrue(assessment.decisionTrace.invariantChecks.all { it.passed })
        assertTrue(assessment.userRiskStory.primaryReason.contains("platform", ignoreCase = true))
    }

    @Test
    fun unknownEvidenceAloneDoesNotBecomeRed() {
        val snapshot = TestSnapshots.app(
            packageName = "com.example.unknown",
            installerPackageName = null
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.GRAY, assessment.decision.color)
        assertFalse(assessment.decision.userAlert)
        assertTrue(assessment.riskVector.provenanceTrust < assessment.riskVector.provenanceConfidence)
        assertTrue(assessment.decisionTrace.thresholdInputs.containsKey("provenanceTrust"))
        assertTrue(assessment.decisionTrace.thresholdInputs.containsKey("provenanceClassificationConfidence"))
        assertTrue(assessment.decision.recommendedActions.any { it.actionId == "abstain_collect_more_context" })
        assertTrue(assessment.decisionTrace.evaluatedRules.any { it.ruleId == "GRAY_UNKNOWN_LOW_EXPOSURE" && it.matched })
    }

    @Test
    fun sideloadWithActiveRiskyCapabilitiesCanBecomeRed() {
        val snapshot = TestSnapshots.app(
            packageName = "com.flashlight.cleaner.update",
            appLabel = "Security Update",
            installerPackageName = null,
            requestedPermissions = listOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            specialAccess = TestSnapshots.defaultSpecialAccess() + mapOf(
                "accessibility_service" to ObservabilityState.OBSERVED_ENABLED,
                "notification_listener" to ObservabilityState.OBSERVED_ENABLED,
                "overlay" to ObservabilityState.OBSERVED_ENABLED
            )
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.RED, assessment.decision.color)
        assertTrue(assessment.decision.userAlert)
        assertTrue(assessment.decision.recommendedActions.any { it.actionId == "disable_risky_special_access" })
        assertTrue(assessment.decision.recommendedActions.any { it.actionabilityClass == ActionabilityClass.USER_CAN_UNINSTALL })
        assertTrue(assessment.decision.recommendedActions.any { it.destructive })
        assertTrue(assessment.decisionTrace.evaluatedRules.any { it.ruleId == "RED_USER_ACTIONABLE_THREAT" && it.matched })
        assertTrue(assessment.decisionTrace.counterfactuals.any { it.targetDecision == DecisionColor.YELLOW })
        assertFalse(
            assessment.decisionTrace.counterfactuals
                .flatMap { it.requiredChanges }
                .any { it.contains("uninstall", ignoreCase = true) }
        )
        assertTrue(assessment.decisionTrace.invariantChecks.all { it.passed })
        assertEquals("Action required", assessment.userRiskStory.headline)
    }

    @Test
    fun deceptiveSideloadDeclaringAccessibilityServiceCanStillBecomeRed() {
        val snapshot = TestSnapshots.app(
            packageName = "com.flashlight.cleaner.update",
            appLabel = "Security Update",
            installerPackageName = null,
            requestedPermissions = listOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            components = listOf(
                ObservedComponent(
                    name = "com.flashlight.cleaner.update.FakeAccessibilityService",
                    type = "service",
                    exported = true,
                    permission = "android.permission.BIND_ACCESSIBILITY_SERVICE"
                )
            ),
            specialAccess = TestSnapshots.defaultSpecialAccess() + mapOf(
                "accessibility_service" to ObservabilityState.OBSERVED_ENABLED,
                "notification_listener" to ObservabilityState.OBSERVED_ENABLED,
                "overlay" to ObservabilityState.OBSERVED_ENABLED
            )
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.RED, assessment.decision.color)
        assertTrue(assessment.role.predicted.name != "ACCESSIBILITY_TOOL")
    }

    @Test
    fun androidFrameworkPackageIsNotTreatedAsAccessibilityTool() {
        val snapshot = TestSnapshots.app(
            packageName = "android",
            appLabel = "Android System",
            installerPackageName = null,
            sourceDir = "/system/framework/framework-res.apk",
            isSystemApp = true,
            isPrivilegedApp = false,
            requestedPermissions = listOf("android.permission.READ_PHONE_STATE"),
            grantedPermissions = listOf("android.permission.READ_PHONE_STATE")
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.GREEN, assessment.decision.color)
        assertEquals("SYSTEM_COMPONENT", assessment.role.predicted.name)
        assertFalse(assessment.decision.userAlert)
    }

    @Test
    fun lowExposureRroSystemPackageIsGreenNotYellow() {
        val snapshot = TestSnapshots.app(
            packageName = "android.auto_generated_rro_product__",
            appLabel = "android.auto_generated_rro_product__",
            installerPackageName = null,
            sourceDir = "/product/overlay/android.auto_generated_rro_product__.apk",
            isSystemApp = true,
            isPrivilegedApp = false
        )

        val assessment = engine.assess(snapshot)

        assertEquals(DecisionColor.GREEN, assessment.decision.color)
        assertFalse(assessment.decision.userAlert)
    }

    @Test
    fun androidProviderPackageIsSystemComponentNotDialer() {
        val snapshot = TestSnapshots.app(
            packageName = "com.android.providers.telephony",
            appLabel = "Phone and Messaging Storage",
            installerPackageName = null,
            sourceDir = "/system/priv-app/TelephonyProvider/TelephonyProvider.apk",
            isSystemApp = true,
            isPrivilegedApp = true,
            requestedPermissions = listOf("android.permission.READ_PHONE_STATE"),
            grantedPermissions = listOf("android.permission.READ_PHONE_STATE")
        )

        val assessment = engine.assess(snapshot)

        assertEquals("SYSTEM_COMPONENT", assessment.role.predicted.name)
        assertFalse(assessment.decision.userAlert)
    }
}
