"""Repository guidance and source-only documentation contracts."""
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class ProjectDocumentationTests(unittest.TestCase):
    def test_guidance_is_well_formed_xml_with_existing_paths(self):
        guidance = ET.parse(ROOT / "AGENTS.md").getroot()
        self.assertEqual(guidance.tag, "project-guidance")
        self.assertEqual(guidance.attrib["project"], "WebAuthn Browser")
        for section in ("architecture", "language-and-names", "browser-lifecycle",
                        "authorization-and-transports", "validation", "release-and-packaging"):
            self.assertIsNotNone(guidance.find(section), section)

        for node in guidance.iter():
            if "path" in node.attrib:
                path = (ROOT / node.attrib["path"]).resolve()
                self.assertTrue(path.is_relative_to(ROOT), path)
                self.assertTrue(path.exists(), path)
            if "cwd" in node.attrib:
                self.assertTrue((ROOT / node.attrib["cwd"]).is_dir())

    def test_documentation_relative_links_resolve(self):
        files = [ROOT / "README.md", ROOT / "TESTING.md", ROOT / "helper/README.md"]
        files += list((ROOT / "docs").rglob("*.md"))
        files += list((ROOT / "tests").rglob("README*.md"))
        files += [ROOT / "native-hid-hook/README.md"]
        files += list((ROOT / "native-hid-hook/tests").glob("README*.md"))
        for document in files:
            for target in re.findall(r"\[[^\]]*\]\(([^)\s]+)\)", document.read_text()):
                parts = urlsplit(target)
                if parts.scheme or parts.netloc or target.startswith(("/", "#")):
                    continue
                self.assertTrue((document.parent / unquote(parts.path)).exists(),
                                f"{document.relative_to(ROOT)}: {target}")

    def test_human_titles_do_not_rename_technical_artifact_paths(self):
        workflow = (ROOT / ".github/workflows/helper.yml").read_text()
        self.assertTrue(workflow.startswith("name: Helper\n"))
        self.assertIn("name: ${{ steps.package.outputs.package_name }}-${{ matrix.platform }}", workflow)
        self.assertIn("tomllib.load(open('Cargo.toml', 'rb'))['package']['name']", workflow)
        self.assertTrue((ROOT / "README.md").read_text().startswith("# WebAuthn Browser\n"))

    def test_readme_ends_with_requested_license(self):
        self.assertTrue((ROOT / "README.md").read_text().endswith(
            "## License\n\nCopyright (c) Cnily03. All rights reserved.\n\n"
            "Licensed under the [GPL-3.0-or-later](LICENSE) license.\n"))

    def test_hidden_host_data_mount_and_migration_are_explicit(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn('"./.data:/data"', compose)
        self.assertNotIn('"./data:/data"', compose)
        readme = (ROOT / "README.md").read_text()
        self.assertIn("stop the container", readme)
        self.assertIn("do not overwrite", readme)
        for ignore in (".gitignore", ".dockerignore"):
            self.assertIn(".data", (ROOT / ignore).read_text())


if __name__ == "__main__":
    unittest.main()
