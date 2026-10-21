plugins { id("com.android.application") }

android {
    namespace = "com.cindersocket.dfc.sample"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.cindersocket.dfc.sample"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies { implementation(project(":dfc")) }
