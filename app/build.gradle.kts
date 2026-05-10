plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
    id("com.google.devtools.ksp")
    kotlin("kapt")
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

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.google.android.material:material:1.12.0")

    implementation(platform("androidx.compose:compose-bom:2025.01.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.5")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.core:core-splashscreen:1.0.1")

    implementation("com.google.dagger:hilt-android:2.52")
    kapt("com.google.dagger:hilt-compiler:2.52")

    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("androidx.datastore:datastore-core:1.1.1")

    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    ksp("com.squareup.moshi:moshi-kotlin-codegen:1.15.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    testImplementation("com.squareup.moshi:moshi-adapters:1.15.1")

    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
