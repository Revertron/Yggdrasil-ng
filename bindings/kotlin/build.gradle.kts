import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// JVM build of the Kotlin bindings, used for the tests. On Android, add
// src/main/kotlin to an Android library module instead, together with the
// per-ABI libyggdrasil_uniffi.so files (see docs/LIBRARY.md).
plugins {
    kotlin("jvm") version "2.0.21"
}

group = "org.yggdrasil"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0")
    testImplementation(kotlin("test"))
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

// Directory holding libyggdrasil_uniffi.so (default: the workspace debug build).
val nativeDir = (findProperty("yggNativeDir") as String?)
    ?: rootProject.projectDir.resolve("../../target/debug").canonicalPath

tasks.test {
    useJUnitPlatform()
    systemProperty("jna.library.path", nativeDir)
    // YggStream wraps raw descriptors via java.io.FileDescriptor on the JVM.
    jvmArgs("--add-opens", "java.base/java.io=ALL-UNNAMED")
    testLogging { events("passed", "failed", "skipped"); showStandardStreams = true }
}
