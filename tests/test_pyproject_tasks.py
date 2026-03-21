from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


class PoeTaskConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pyproject = tomllib.loads(
            Path("pyproject.toml").read_text(encoding="utf-8")
        )

    def test_dev_group_includes_poe_the_poet(self) -> None:
        dev_dependencies = self.pyproject["dependency-groups"]["dev"]

        self.assertTrue(
            any(dependency.startswith("poethepoet") for dependency in dev_dependencies),
            msg="poethepoet should be available in the dev dependency group",
        )

    def test_poe_tasks_cover_quality_checks_and_softphone_runner(self) -> None:
        tasks = self.pyproject["tool"]["poe"]["tasks"]

        self.assertEqual(tasks["format"], "ruff format .")
        self.assertEqual(tasks["lint"], "ruff check .")
        self.assertEqual(tasks["lint-fix"], "ruff check . --fix")
        self.assertEqual(tasks["type-check"], "ty check")
        self.assertEqual(tasks["softphone-run"], "python scripts/run_baresip.py")


if __name__ == "__main__":
    unittest.main()
