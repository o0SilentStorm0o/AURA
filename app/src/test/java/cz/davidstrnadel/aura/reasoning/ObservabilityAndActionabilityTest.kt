package cz.davidstrnadel.aura.reasoning

import cz.davidstrnadel.aura.core.ActionabilityClass
import cz.davidstrnadel.aura.core.ObservabilityState
import org.junit.Assert.assertEquals
import org.junit.Test

class ObservabilityAndActionabilityTest {
    @Test
    fun observabilityEnumIsExactResearchContract() {
        assertEquals(
            listOf(
                "OBSERVED_ENABLED",
                "OBSERVED_DISABLED",
                "DECLARED_ONLY",
                "USER_GRANT_REQUIRED",
                "REQUIRES_RESEARCH_FLAVOR",
                "ADB_ONLY",
                "DEVICE_OWNER_ONLY",
                "ROOT_OR_OEM_ONLY",
                "NOT_OBSERVABLE",
                "UNKNOWN_API_LIMITATION"
            ),
            ObservabilityState.entries.map { it.name }
        )
    }

    @Test
    fun actionabilityEnumContainsUserAndPlatformSeparation() {
        assertEquals(
            listOf(
                "USER_CAN_REVOKE_PERMISSION",
                "USER_CAN_DISABLE_SPECIAL_ACCESS",
                "USER_CAN_UNINSTALL",
                "USER_CAN_ONLY_REVIEW",
                "OEM_OR_PLATFORM_ONLY",
                "REQUIRES_ENTERPRISE_ADMIN",
                "NOT_ACTIONABLE"
            ),
            ActionabilityClass.entries.map { it.name }
        )
    }
}
