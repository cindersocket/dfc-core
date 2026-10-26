pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        providers.gradleProperty("dfcRepository").orNull?.let { maven { url = uri(it) } }
        google()
        mavenCentral()
    }
}
rootProject.name = "dfc-android"
include(":dfc", ":sample")
project(":sample").projectDir = file("../../examples/android")
if (providers.gradleProperty("dfcPackageConsumer").orNull == "true") {
    include(":package-consumer")
    project(":package-consumer").projectDir = file("../../tests/package-consumer/android/app")
}
