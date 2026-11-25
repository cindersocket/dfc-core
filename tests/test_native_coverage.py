"""Regression tests for native coverage evidence separation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = Path(__file__).with_name("run_native_coverage.py")
SPEC = importlib.util.spec_from_file_location("run_native_coverage", MODULE_PATH)
assert SPEC and SPEC.loader
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)


class NativeCoverageTests(unittest.TestCase):
    def test_repository_contract_has_every_behavior_family(self) -> None:
        contract = COVERAGE.load_contract()
        minimums = COVERAGE.validate_coverage_history(contract)
        COVERAGE.validate_behavior_matrix(
            contract,
            ROOT / "tests" / "vectors" / "desfire" / "manifest.json",
            ROOT,
        )

        self.assertEqual(set(minimums), set(COVERAGE.MINIMUM_PERCENT))
        self.assertEqual(
            {row["family"] for row in contract["behaviors"]},
            COVERAGE.REQUIRED_BEHAVIOR_FAMILIES,
        )

    def test_coverage_history_cannot_lower_a_floor(self) -> None:
        contract = {
            "coverage_history": [
                {
                    "label": "baseline",
                    "minimum_percent": COVERAGE.MINIMUM_PERCENT,
                },
                {
                    "label": "lowered",
                    "minimum_percent": {
                        **COVERAGE.MINIMUM_PERCENT,
                        "physical": {
                            **COVERAGE.MINIMUM_PERCENT["physical"],
                            "branches": 53.9,
                        },
                    },
                },
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "lowers physical branches"):
            COVERAGE.validate_coverage_history(contract)

    def test_gap_contract_rejects_unclassified_and_stale_symbols(self) -> None:
        gap = {
            "file": "dfc_emulator.c",
            "function": "visible_gap",
        }
        contract = {
            "gap_classifications": [
                {
                    "file": "dfc_emulator.c",
                    "function": "old_gap",
                    "category": "capture-derived",
                    "rationale": "Covered through its enclosing command.",
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "unclassified: .*visible_gap.*stale: .*old_gap"):
            COVERAGE.validate_gap_classifications([gap], contract)

    def test_gap_contract_counts_only_known_categories(self) -> None:
        gap = {"file": "dfc_emulator.c", "function": "visible_gap"}
        entry = {
            **gap,
            "category": "capture-required",
            "rationale": "Wire-visible behavior needs a physical replay.",
        }

        counts = COVERAGE.validate_gap_classifications([gap], {"gap_classifications": [entry]})
        self.assertEqual(counts["capture-required"], 1)

        entry["category"] = "ignored"
        with self.assertRaisesRegex(RuntimeError, "invalid category"):
            COVERAGE.validate_gap_classifications([gap], {"gap_classifications": [entry]})

    def test_ratcheted_minimums_round_down_without_lowering(self) -> None:
        metrics = {
            "all": {
                "lines": {"percent": 90.39},
                "branches": {"percent": 79.04},
                "functions": {"percent": 96.99},
            },
            "physical": {
                "lines": {"percent": 68.69},
                "branches": {"percent": 55.01},
                "functions": {"percent": 80.89},
            },
        }

        ratcheted = COVERAGE.ratcheted_minimums(COVERAGE.MINIMUM_PERCENT, metrics)

        self.assertEqual(ratcheted["all"]["lines"], 90.3)
        self.assertEqual(ratcheted["all"]["functions"], 97.0)
        self.assertEqual(ratcheted["physical"]["branches"], 55.0)

    def test_vector_modes_are_disjoint_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "files": [
                            {
                                "path": "physical.vec",
                                "metadata": {
                                    "origin": "physical-card",
                                    "replayable": True,
                                },
                            },
                            {
                                "path": "synthetic.vec",
                                "metadata": {"origin": "synthetic", "replayable": True},
                            },
                            {
                                "path": "transcript.vec",
                                "metadata": {
                                    "origin": "physical-card",
                                    "replayable": False,
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            physical = COVERAGE.vector_paths(manifest, "physical-card")
            synthetic = COVERAGE.vector_paths(manifest, "synthetic")
            all_vectors = COVERAGE.vector_paths(manifest, None)

            self.assertEqual(physical, [root / "physical.vec"])
            self.assertEqual(synthetic, [root / "synthetic.vec"])
            self.assertEqual(all_vectors, physical + synthetic)

    def test_capture_queue_counts_only_tested_regions_missing_on_hardware(self) -> None:
        all_payload = {
            "data": [
                {
                    "functions": [
                        {
                            "name": "covered_function",
                            "count": 4,
                            "filenames": ["/tmp/source/src/dfc_emulator.c"],
                            "branches": [
                                [10, 1, 10, 8, 4, 2, 0, 0, 4],
                                [12, 1, 12, 8, 3, 0, 0, 0, 4],
                            ],
                            "regions": [
                                [10, 1, 12, 2, 4, 0, 0, 0],
                                [11, 1, 11, 8, 0, 0, 0, 0],
                                [12, 1, 12, 8, 3, 0, 0, 0],
                            ],
                        },
                        {
                            "name": "test_helper",
                            "count": 1,
                            "filenames": ["/tmp/source/tests/test_helper.c"],
                            "branches": [],
                            "regions": [[1, 1, 2, 2, 1, 0, 0, 0]],
                        },
                    ]
                }
            ]
        }
        physical_payload = {
            "data": [
                {
                    "functions": [
                        {
                            "name": "covered_function",
                            "count": 0,
                            "filenames": ["/tmp/source/src/dfc_emulator.c"],
                            "branches": [
                                [10, 1, 10, 8, 0, 0, 0, 0, 4],
                                [12, 1, 12, 8, 0, 0, 0, 0, 4],
                            ],
                            "regions": [
                                [10, 1, 12, 2, 0, 0, 0, 0],
                                [11, 1, 11, 8, 0, 0, 0, 0],
                                [12, 1, 12, 8, 0, 0, 0, 0],
                            ],
                        }
                    ]
                }
            ]
        }

        gaps = COVERAGE.capture_gaps_from_payloads(
            all_payload, physical_payload, {"dfc_emulator.c"}
        )

        self.assertEqual(
            gaps,
            [
                {
                    "file": "dfc_emulator.c",
                    "line": 10,
                    "function": "covered_function",
                    "function_missing_physical_evidence": True,
                    "covered_branch_outcomes_missing_physical_evidence": 3,
                    "covered_regions_missing_physical_evidence": 2,
                }
            ],
        )

    def test_capture_queue_uses_the_runtime_filename_from_multi_file_symbols(
        self,
    ) -> None:
        payload = {
            "data": [
                {
                    "functions": [
                        {
                            "name": "shared_symbol",
                            "count": 1,
                            "filenames": [
                                "/tmp/source/tests/renamed_source_test.c",
                                "/tmp/source/src/dfc_credential.c",
                            ],
                            "branches": [],
                            "regions": [[20, 1, 21, 1, 1, 1, 0, 0]],
                        }
                    ]
                }
            ]
        }

        functions = COVERAGE.function_regions(payload, {"dfc_credential.c"})

        self.assertEqual(functions[("dfc_credential.c", "shared_symbol")]["line"], 20)

    def test_makefile_coverage_excludes_alternate_profiles(self) -> None:
        text = (ROOT / "tests" / "Makefile").read_text(encoding="utf-8")

        self.assertIn("$(MAKE) coverage-instrumented COVERAGE=1 CC=clang", text)
        self.assertIn("coverage-instrumented: $(COVERAGE_TESTS) $(CONFORMANCE_RUNNER)", text)
        self.assertIn("$(CONFORMANCE_RUNNER)", text)
        coverage_assignment = text.split("COVERAGE_TESTS :=", 1)[1].split("\n\n", 1)[0]
        self.assertNotIn("REDUCED_TESTS", coverage_assignment)
        self.assertNotIn("CONFORMANCE_PROFILE_RUNNERS", coverage_assignment)

    def test_emulator_scope_includes_shared_runtime_dependencies(self) -> None:
        names = {path.name for path in COVERAGE.coverage_sources(ROOT)}

        self.assertIn("dfc_credential.c", names)
        self.assertIn("dfc_transaction_mac.c", names)
        self.assertIn("dfc_sdm.c", names)
        self.assertIn("dfc_crypto.c", names)
        self.assertNotIn("dfc_reader.c", names)
        self.assertNotIn("dfc_text.c", names)

    def test_coverage_minimums_reject_regressions(self) -> None:
        metrics = {
            mode: {category: {"percent": minimum} for category, minimum in categories.items()}
            for mode, categories in COVERAGE.MINIMUM_PERCENT.items()
        }
        COVERAGE.enforce_minimums(metrics)

        metrics["physical"]["branches"]["percent"] -= 0.01
        with self.assertRaisesRegex(RuntimeError, "physical branches"):
            COVERAGE.enforce_minimums(metrics)

    def test_public_script_uses_an_isolated_copy(self) -> None:
        text = (ROOT / "scripts" / "run-native-coverage.sh").read_text(encoding="utf-8")

        self.assertIn("mktemp -d", text)
        self.assertIn('make -C "$work_dir/tests" coverage', text)
        self.assertNotIn('make -C "$repo_root/tests"', text)


if __name__ == "__main__":
    unittest.main()
