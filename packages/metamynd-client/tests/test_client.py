"""Checks about the package itself: the pieces that are easy to change in one place and forget in another."""

from __future__ import annotations

import re
import subprocess
import sys
import unittest

from _support import PACKAGE, SRC

import metamynd_client


class Package(unittest.TestCase):
    def test_the_module_version_matches_pyproject(self) -> None:
        pyproject = (PACKAGE / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(metamynd_client.__version__, declared, "bump both together: PyPI refuses to overwrite a released version")

    def test_the_public_surface_is_exported(self) -> None:
        for name in ("MetaMyndClient", "Verdict", "SignedRequest", "EscalationStatus", "Outcome", "SettlementResult", "guard_tool", "governance_headers", "current_governance", "GovernanceBlocked", "canonical_message"):
            self.assertIn(name, metamynd_client.__all__)
            self.assertTrue(hasattr(metamynd_client, name), name)

    def test_the_selftest_passes_as_a_subprocess(self) -> None:
        done = subprocess.run([sys.executable, "-m", "metamynd_client", "--selftest"], cwd=str(SRC), capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        self.assertIn("selftest ok", done.stdout)

    def test_the_docs_and_package_copies_are_identical(self) -> None:
        from _support import EXAMPLES

        self.assertEqual((EXAMPLES / "metamynd_client.py").read_bytes(), (SRC / "metamynd_client.py").read_bytes(), "run: node scripts/examples/publish-python-client.mjs")


class ReleaseWorkflow(unittest.TestCase):
    """The PyPI workflow's two load-bearing properties, so neither can be dropped in a later edit.

    Publishing was manual-only, and the manual step was forgotten: 0.1.0 stayed on PyPI signing the wrong number of
    fields while the fix sat merged and tagged. It now runs on every release tag, like the npm workflow. And it is
    GATED: a client that signs the wrong bytes must not be releasable, so the conformance tests run before the upload.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from _support import REPO

        cls.text = (REPO / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8")

    def test_it_runs_on_every_release_tag_and_can_still_be_run_by_hand(self) -> None:
        self.assertRegex(self.text, r'on:\s*\n\s+push:\s*\n\s+tags:\s*\n\s+- "v\*"', "must trigger on `v*` tags, like publish-packages.yml")
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("dry_run:", self.text)

    def test_the_conformance_tests_run_before_anything_is_published(self) -> None:
        gate = self.text.index("python -m unittest discover -s tests")
        selftest = self.text.index("--selftest")
        publish = self.text.index("pypa/gh-action-pypi-publish")
        self.assertLess(selftest, gate)
        self.assertLess(gate, publish, "the conformance tests must run BEFORE the upload step")

    def test_an_already_published_version_is_a_no_op_and_only_one_publish_runs_at_a_time(self) -> None:
        self.assertIn("already_published", self.text)
        self.assertIn("group: publish-pypi", self.text)
        self.assertIn("cancel-in-progress: false", self.text)
        # a tag push has no `dry_run` input, which must read as "publish", not "skip"
        self.assertIn("!inputs.dry_run", self.text)

    def test_it_uses_trusted_publishing_not_a_stored_token(self) -> None:
        self.assertIn("id-token: write", self.text)
        self.assertIn("environment: pypi", self.text)
        self.assertNotIn("PYPI_TOKEN", self.text)
        self.assertNotIn("password:", self.text)

    def test_the_public_package_page_never_names_the_private_repository(self) -> None:
        """metamynd-client is a public package; like the npm ones it is published under MetaMynd, not under the account
        that hosts the private repository. The publish action attaches PUBLIC attestations by default, which would print
        `<owner>/AgentSafe` on the PyPI page — so they must be switched off (npm provenance is off for the same reason)."""
        publish = self.text[self.text.index("pypa/gh-action-pypi-publish") :]
        step = publish[: publish.index("- name:")]
        self.assertRegex(step, r"attestations:\s*false", "the publish step must disable public attestations")

    def test_the_package_metadata_says_metamynd_not_a_personal_account(self) -> None:
        from _support import PACKAGE

        pyproject = (PACKAGE / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('authors = [{ name = "MetaMynd" }]', pyproject)
        self.assertIn("github.com/Metamynd/agentsafe-guard", pyproject)
        # ("AgentSafe" is the product's public name; what must not appear is the personal account that hosts the private repo.)
        self.assertNotIn("jasimp18", pyproject)
        self.assertNotIn("§7.3", pyproject, "the signed message is spec §8.3 (§7.3 is 'Reassessment')")


if __name__ == "__main__":
    unittest.main()
