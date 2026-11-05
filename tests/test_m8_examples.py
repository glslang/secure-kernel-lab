from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from sklab.m8_examples import EXAMPLE_FILES, generate


class M8ExampleTests(unittest.TestCase):
    def test_committed_examples_match_the_production_generators(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        committed = repository / "examples" / "m8"
        with tempfile.TemporaryDirectory() as directory:
            regenerated = Path(directory)
            generate(regenerated)
            for relative in EXAMPLE_FILES:
                self.assertEqual(
                    (regenerated / relative).read_bytes(),
                    (committed / relative).read_bytes(),
                    f"regenerate {relative} with scripts/generate_m8_examples.py",
                )

    def test_committed_examples_contain_no_live_authority(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        combined = "\n".join(
            (repository / "examples" / "m8" / relative).read_text(
                encoding="utf-8"
            )
            for relative in EXAMPLE_FILES
        )
        self.assertIn("${SKLAB_ROOT}", combined)
        self.assertIn("${SKLAB_REPO}", combined)
        self.assertIn("${PYTHON}", combined)
        self.assertIn("00000000-0000-0000-0000-000000000000", combined)
        self.assertNotIn(str(repository), combined)
        self.assertNotIn("password", combined.lower())


if __name__ == "__main__":
    unittest.main()
