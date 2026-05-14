plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

android {
    namespace = "cz.davidstrnadel.aura"
    compileSdk = 35

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "cz.davidstrnadel.aura"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-research"
        vectorDrawables { useSupportLibrary = true }

        buildConfigField("String", "COLLECTOR_VERSION", "\"aura-collector-0.1.0\"")
    }

    flavorDimensions += listOf("distribution", "capability")

    productFlavors {
        create("researchFull") {
            dimension = "distribution"
            applicationIdSuffix = ".research"
            versionNameSuffix = "-research"
            buildConfigField("Boolean", "AURA_FULL_INVENTORY", "true")
            buildConfigField("String", "AURA_DISTRIBUTION_FLAVOR", "\"researchFull\"")
        }
        create("playSafe") {
            dimension = "distribution"
            applicationIdSuffix = ".playsafe"
            versionNameSuffix = "-playsafe"
            buildConfigField("Boolean", "AURA_FULL_INVENTORY", "false")
            buildConfigField("String", "AURA_DISTRIBUTION_FLAVOR", "\"playSafe\"")
        }
        create("standard") {
            dimension = "capability"
            buildConfigField("String", "AURA_CAPABILITY_FLAVOR", "\"standard\"")
            buildConfigField("Boolean", "AURA_LAB_ACCESSIBILITY", "false")
            buildConfigField("Boolean", "AURA_ENTERPRISE_PROTOTYPE", "false")
        }
        create("labAccessibility") {
            dimension = "capability"
            applicationIdSuffix = ".labaccessibility"
            versionNameSuffix = "-lab-accessibility"
            buildConfigField("String", "AURA_CAPABILITY_FLAVOR", "\"labAccessibility\"")
            buildConfigField("Boolean", "AURA_LAB_ACCESSIBILITY", "true")
            buildConfigField("Boolean", "AURA_ENTERPRISE_PROTOTYPE", "false")
        }
        create("enterprisePrototype") {
            dimension = "capability"
            applicationIdSuffix = ".enterprise"
            versionNameSuffix = "-enterprise"
            buildConfigField("String", "AURA_CAPABILITY_FLAVOR", "\"enterprisePrototype\"")
            buildConfigField("Boolean", "AURA_LAB_ACCESSIBILITY", "false")
            buildConfigField("Boolean", "AURA_ENTERPRISE_PROTOTYPE", "true")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.android.material)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.core.splashscreen)

    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.datastore.core)

    implementation(libs.moshi.kotlin)
    ksp(libs.moshi.kotlin.codegen)

    testImplementation(libs.junit)
    testImplementation(libs.moshi.kotlin)
    testImplementation(libs.moshi.adapters)

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
