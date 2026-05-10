plugins {
    id("com.android.application")
}

android {
    namespace = "org.fdroid.example.screenreader"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.fdroid.example.screenreader"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
}
