pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "AURA"
include(":app")
include(":testapps:suspicious-agent")
include(":testapps:benign-accessibility")
include(":testapps:lowrisk-utility")
include(":testapps:sensitive-bank")
