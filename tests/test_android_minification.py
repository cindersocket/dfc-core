import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class AndroidMinificationPolicyTests(unittest.TestCase):
    def test_native_exception_survives_minified_sample(self) -> None:
        consumer_rules = (ROOT / "bindings/android/dfc/consumer-rules.pro").read_text()
        sample_build = (ROOT / "examples/android/build.gradle.kts").read_text()
        smoke_test = (
            ROOT
            / "examples/android/src/androidTest/java/com/cindersocket/dfc/sample/MinifiedExceptionTest.java"
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
        self.assertIn('DfcCredentialCodec.parse("not a credential")', smoke_test)
        self.assertIn(":sample:connectedReleaseAndroidTest", workflow)


if __name__ == "__main__":
    unittest.main()
