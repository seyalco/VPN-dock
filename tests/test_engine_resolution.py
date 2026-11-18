"""Check sing-box discovery without relying on the host's installation."""

from contextlib import ExitStack
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from vpngate.core import SingBoxMissingError, find_sing_box


class EngineResolutionTest(unittest.TestCase):
    def setUp(self):
        scope = ExitStack()
        self.addCleanup(scope.close)
        self.root = Path(scope.enter_context(TemporaryDirectory()))
        self.project = self.root / "checkout"
        self.launcher = self.root / "portable"
        self.home = self.root / "home"
        self.data_home = self.root / "appdata"
        self.path_dir = self.root / "usr-bin"
        scope.enter_context(patch("vpngate.core.ROOT", self.project / "vpngate"))
        scope.enter_context(patch.dict(os.environ, {
            "HOME": str(self.home),
            "PATH": str(self.path_dir),
        }, clear=True))

    def engine_at(self, path, *, executable=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        path.chmod(0o755 if executable else 0o644)
        return path

    def test_searches_app_locations_then_local_install_then_path(self):
        with patch.dict(os.environ, {"VPNDOCK_LAUNCHER_DIR": str(self.launcher)}):
            candidates = (
                self.engine_at(self.launcher / "bin/sing-box"),
                self.engine_at(self.launcher / "sing-box"),
                self.engine_at(self.project / "bin/sing-box"),
                self.engine_at(self.project / "sing-box"),
                self.engine_at(self.home / ".local/share/vpndock/bin/sing-box"),
                self.engine_at(self.home / ".local/bin/sing-box"),
                self.engine_at(self.path_dir / "sing-box"),
            )
            for candidate in candidates:
                with self.subTest(candidate=candidate):
                    self.assertEqual(find_sing_box(), str(candidate))
                    candidate.unlink()

    def test_xdg_data_location_skips_non_executable_candidate(self):
        self.engine_at(self.data_home / "vpndock/bin/sing-box", executable=False)
        fallback = self.engine_at(self.home / ".local/bin/sing-box")
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(self.data_home)}):
            self.assertEqual(find_sing_box(), str(fallback))
            engine = self.engine_at(self.data_home / "vpndock/bin/sing-box")
            self.assertEqual(find_sing_box(), str(engine))

    def test_explicit_override_wins_and_failed_override_is_actionable(self):
        self.engine_at(self.project / "bin/sing-box")
        engine = self.engine_at(self.home / "preferred-engine")
        with patch.dict(os.environ, {"VPNDOCK_SING_BOX": "~/preferred-engine"}):
            self.assertEqual(find_sing_box(), str(engine))
            engine.unlink()
            with self.assertRaisesRegex(SingBoxMissingError, "VPNDOCK_SING_BOX.*executable"):
                find_sing_box()

    def test_reports_how_to_install_a_missing_engine(self):
        with self.assertRaisesRegex(SingBoxMissingError, r"chmod \+x ~/\.local/bin/sing-box"):
            find_sing_box()
