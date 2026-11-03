import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Android library wrapping the Kotlin bindings (../kotlin/src/main/kotlin)
// and libyggdrasil_uniffi.so. Its instrumented tests run the shared binding
// tests plus Android-specific ones on a device or emulator:
//
//   ./build-native.sh                  # cargo-ndk -> build/jniLibs/<abi>/
//   gradle connectedDebugAndroidTest   # with a device/emulator attached
//
// Needs Gradle 8.14 (AGP 8.7 does not support Gradle 9).
plugins {
    id("com.android.library") version "8.7.3"
    kotlin("android") version "2.0.21"
}

android {
    namespace = "link.yggdrasil.embed"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            java.srcDir("../kotlin/src/main/kotlin")
            jniLibs.srcDir("build/jniLibs")
        }
        getByName("androidTest") {
            // The JVM test suite runs unchanged on Android.
            java.srcDir("../kotlin/src/test/kotlin")
            java.srcDir("src/androidTest/kotlin")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        // Keep symbols readable in native crash reports from test runs.
        jniLibs.keepDebugSymbols += "**/libyggdrasil_uniffi.so"
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation(kotlin("test-junit"))
}
