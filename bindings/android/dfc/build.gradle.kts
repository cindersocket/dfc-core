plugins { id("com.android.library") }

android {
    namespace = "com.cindersocket.dfc"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86") }
        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DDFC_BUILD_JNI=ON", "-DDFC_BUILD_SHARED=OFF", "-DDFC_BUILD_TESTS=OFF",
                    "-DDFC_ROLE=simulator", "-DDFC_PROFILE=full_ev3", "-DDFC_CRYPTO=tiny"
                )
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
    buildTypes { release { isMinifyEnabled = false } }
}
