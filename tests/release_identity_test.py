"""Release tooling follows distribution metadata without fixing an organization."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseIdentityTests(unittest.TestCase):
    def test_notes_use_the_workspace_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text('[workspace.package]\nrepository = "https://github.com/example-org/standalone-agent"\n')
            (root / "CHANGELOG.md").write_text('## [1.2.3]\n\n- Fixture release.\n')
            output = root / "notes.md"
            with patch.object(release, "ROOT", root):
                release.notes("1.2.3", output)
            self.assertIn("https://github.com/example-org/standalone-agent/blob/v1.2.3/documentation/release-verification.md", output.read_text())

    def test_image_repository_command_reads_chart_distribution_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            shutil.copyfile(ROOT / "scripts/release.py", root / "scripts/release.py")
            chart = root / "charts/e-navigator"
            chart.mkdir(parents=True)
            (chart / "values.yaml").write_text('image:\n  repository: registry.example.com/standalone/agent\n  tag: ""\n')
            result = subprocess.run([sys.executable, str(root / "scripts/release.py"), "image-repository"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "registry.example.com/standalone/agent")


if __name__ == "__main__":
    unittest.main()
