import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.tasks.GenerateModuleMetadata
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.jvm.tasks.Jar

plugins {
    id("com.android.library")
    id("maven-publish")
}

group = "com.cindersocket"
version = "2.0.0"

dependencies {
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

android {
    namespace = "com.cindersocket.dfc"
    compileSdk = 36
    ndkVersion = providers.gradleProperty("dfc.ndkVersion").get()
    testBuildType = "mismatch"

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86") }
        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DDFC_BUILD_JNI=ON", "-DDFC_BUILD_SHARED=OFF", "-DDFC_BUILD_TESTS=OFF",
                    "-DDFC_ROLE=simulator", "-DDFC_PROFILE=full_ev3", "-DDFC_CRYPTO=tiny"
                )
                System.getenv("DFC_TINY_CRYPTO_DIR")?.let {
                    arguments += "-DDFC_TINY_CRYPTO_DIR=$it"
                }
                targets += "dfc_jni"
            }
        }
    }
    externalNativeBuild {
        cmake {
            path = file("../../../CMakeLists.txt")
            version = "4.1.2"
        }
    }
    sourceSets["main"].java.srcDir("../../java/src/main/java")
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        release { isMinifyEnabled = false }
        create("mismatch") {
            initWith(getByName("debug"))
            externalNativeBuild {
                cmake { cFlags += "-DDFC_FFI_TEST_LAYOUT_FINGERPRINT_XOR=1" }
            }
        }
    }
    publishing { singleVariant("release") { withSourcesJar() } }
}

val androidJavadocs by tasks.registering(Javadoc::class) {
    source = android.sourceSets["main"].java.getSourceFiles()
    classpath += files(android.bootClasspath)
    isFailOnError = true
    (options as StandardJavadocDocletOptions).apply {
        addBooleanOption("Werror", true)
        addBooleanOption("Xdoclint:all", true)
    }
}

val androidJavadocsJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(androidJavadocs)
}

// Compile the same binding-level suite that the host JNI job executes. This
// catches Android source/API drift even though host JVM tests cannot load an Android .so.
val compileSharedAdvancedApiTest by tasks.registering(JavaCompile::class) {
    dependsOn("compileDebugJavaWithJavac")
    source("../../../tests/java/DfcAdvancedApiTest.java")
    classpath = files(
        layout.buildDirectory.dir("intermediates/javac/debug/compileDebugJavaWithJavac/classes")
    ) + configurations["debugCompileClasspath"]
    destinationDirectory.set(layout.buildDirectory.dir("intermediates/shared-advanced-api-test"))
    options.release.set(17)
}

tasks.matching { it.name == "testDebugUnitTest" }.configureEach {
    dependsOn(compileSharedAdvancedApiTest)
}

// Maven Central consumers use the AAR and POM contract declared in the release inventory.
tasks.withType<GenerateModuleMetadata>().configureEach { enabled = false }

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "dfc-core-android"
            afterEvaluate { from(components["release"]) }
            artifact(androidJavadocsJar)
            pom {
                name.set("dfc-core Android binding")
                description.set("Android AAR for the dfc-core DESFire-compatible engine.")
                url.set("https://github.com/cindersocket/dfc-core")
                licenses {
                    license {
                        name.set("GNU General Public License v2.0 or later")
                        url.set("https://www.gnu.org/licenses/old-licenses/gpl-2.0.html")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("cindersocket")
                        name.set("CinderSocket")
                        email.set("cindersocket@users.noreply.github.com")
                        url.set("https://github.com/cindersocket")
                        roles.set(listOf("developer"))
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/cindersocket/dfc-core.git")
                    developerConnection.set("scm:git:ssh://git@github.com/cindersocket/dfc-core.git")
                    url.set("https://github.com/cindersocket/dfc-core")
                    tag.set("HEAD")
                }
            }
        }
    }
    repositories {
        maven {
            name = "build"
            url = uri(rootProject.layout.projectDirectory.dir("build-repository"))
        }
    }
}
