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
        smoke_manifest = (
            ROOT / "examples/android/src/minifiedSmoke/AndroidManifest.xml"
        ).read_text()
        smoke_probe = (
            ROOT
            / "examples/android/src/minifiedSmoke/java/com/cindersocket/dfc/sample/MinifiedExceptionProbeActivity.java"
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
        self.assertIn('testBuildType = "minifiedSmoke"', sample_build)
        self.assertIn('create("minifiedSmoke")', sample_build)
        self.assertIn(
            'androidTestImplementation("com.google.errorprone:error_prone_annotations:',
            sample_build,
        )
        self.assertIn('testProguardFiles("proguard-rules.pro")', sample_build)
        self.assertIn("-dontwarn javax.lang.model.element.Modifier", sample_rules)
        self.assertNotIn("import com.cindersocket.dfc.", smoke_test)
        self.assertIn(".MinifiedExceptionProbeActivity", smoke_manifest)
        self.assertIn('android:exported="false"', smoke_manifest)
        self.assertIn("new DfcReader", smoke_probe)
        self.assertIn("Integer.MAX_VALUE", smoke_probe)
        self.assertIn("DfcReader.Communication.PLAIN, -1", sample_source)
        self.assertIn(
            "script: bindings/android/gradlew --no-daemon -p bindings/android "
            ":sample:connectedMinifiedSmokeAndroidTest :dfc:connectedMismatchAndroidTest",
            workflow,
        )
        kvm_rule = 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"'
        reload_rules = "sudo udevadm control --reload-rules"
        trigger_kvm = "sudo udevadm trigger --name-match=kvm"
        emulator_action = "reactivecircus/android-emulator-runner"
        self.assertIn(kvm_rule, workflow)
        self.assertIn(reload_rules, workflow)
        self.assertIn(trigger_kvm, workflow)
        self.assertLess(
            workflow.index(kvm_rule),
            workflow.index(reload_rules),
        )
        self.assertLess(workflow.index(reload_rules), workflow.index(trigger_kvm))
        self.assertLess(workflow.index(trigger_kvm), workflow.index(emulator_action))
        self.assertNotIn("cd bindings/android\n", workflow)


if __name__ == "__main__":
    unittest.main()
