import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class AndroidMinificationPolicyTests(unittest.TestCase):
    def test_native_exception_survives_minified_sample(self) -> None:
        consumer_rules = (ROOT / "bindings/android/dfc/consumer-rules.pro").read_text()
        sample_build = (ROOT / "examples/android/build.gradle.kts").read_text()
        sample_rules = (ROOT / "examples/android/proguard-rules.pro").read_text()
        smoke_test = (
            ROOT
            / "examples/android/src/androidTest/java/com/cindersocket/dfc/sample/MinifiedExceptionTest.java"
        ).read_text()
        sample_source = (
            ROOT / "examples/android/src/main/java/com/cindersocket/dfc/sample/MainActivity.java"
        ).read_text()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()

        self.assertIn(
            "-keep,allowoptimization class com.cindersocket.dfc.DfcException",
            consumer_rules,
        )
        self.assertIn(
            "public <init>(java.lang.String, int, int, int);",
            consumer_rules,
        )
        self.assertNotIn("-keep class com.cindersocket.dfc.**", consumer_rules)
        self.assertIn("isMinifyEnabled = true", sample_build)
        self.assertNotIn("isDebuggable = true", sample_build)
        self.assertIn('testBuildType = "release"', sample_build)
        self.assertIn(
            'androidTestImplementation("com.google.errorprone:error_prone_annotations:2.30.0")',
            sample_build,
        )
        self.assertIn('testProguardFiles("proguard-rules.pro")', sample_build)
        self.assertIn("-dontwarn javax.lang.model.element.Modifier", sample_rules)
        self.assertIn("new DfcReader", smoke_test)
        self.assertIn("Integer.MAX_VALUE", smoke_test)
        self.assertIn("DfcReader.Communication.PLAIN, -1", sample_source)
        self.assertIn(
            "script: bindings/android/gradlew --no-daemon -p bindings/android "
            ":sample:connectedReleaseAndroidTest :dfc:connectedMismatchAndroidTest",
            workflow,
        )
        self.assertNotIn("cd bindings/android\n", workflow)


if __name__ == "__main__":
    unittest.main()
