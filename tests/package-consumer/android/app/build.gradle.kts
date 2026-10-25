plugins { id("com.android.application") }

android {
    namespace = "com.cindersocket.dfc.consumer"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("com.cindersocket:dfc-core-android:${providers.gradleProperty("dfcVersion").get()}")
}
