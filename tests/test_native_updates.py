"""Synthetic native update core/transport/bridge/journal fixtures; no host telemetry or Keychain."""
from pathlib import Path
import re
import os
import plistlib
import uuid
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeUpdateTests(unittest.TestCase):
    def test_native_update_fixtures(self):
        with tempfile.TemporaryDirectory(prefix="monitor-native-updates-") as directory:
            output = Path(directory)
            binary = output / "update-fixtures"
            sources = sorted((ROOT / "mac").glob("Update*.swift"))
            self.assertGreaterEqual(len(sources), 8)
            compiled = subprocess.run([
                "xcrun", "swiftc", "-module-cache-path", str(output / "module-cache"),
                *map(str, sources), str(ROOT / "tests/native/UpdateFixtures.swift"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=180)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary), str(output)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            match = re.search(r"NATIVE_UPDATE_FIXTURES (\d+)", result.stdout)
            self.assertIsNotNone(match, result.stdout + result.stderr)
            self.assertGreaterEqual(int(match.group(1)), 45)
            closed = subprocess.run([str(binary), "--closed-stderr-lock-probe", str(output / 'closed-stderr')],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(closed.returncode, 0, closed.stdout + closed.stderr)
            self.assertIn("NATIVE_CLOSED_STDERR_LOCK passed", closed.stdout)

    def test_stock_sparkle_effective_flags(self):
        framework = Path(os.environ["MONITOR_SPARKLE_FRAMEWORK_DIR"])
        self.assertTrue((framework / "Sparkle.framework/Sparkle").exists())
        with tempfile.TemporaryDirectory(prefix="monitor-sparkle-flags-") as directory:
            root = Path(directory)
            bundle = root / "Updater Fixture.app"
            contents = bundle / "Contents"
            executable = contents / "MacOS/Flags"
            executable.parent.mkdir(parents=True)
            (contents / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "test.machine-monitor.sparkle." + uuid.uuid4().hex,
                "CFBundleExecutable": "Flags", "CFBundleName": "Updater Fixture",
                "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
                "CFBundlePackageType": "APPL", "SUEnableAutomaticChecks": False,
                "SUAllowsAutomaticUpdates": True, "SUAutomaticallyUpdate": True,
                "SUVerifyUpdateBeforeExtraction": True,
            }))
            compiled = subprocess.run([
                "xcrun", "swiftc", "-parse-as-library", "-F", str(framework),
                "-framework", "Sparkle", "-Xlinker", "-rpath", "-Xlinker", str(framework),
                "-module-cache-path", str(root / "module-cache"),
                str(ROOT / "tests/native/UpdateSparkleFlags.swift"), "-o", str(executable),
            ], capture_output=True, text=True, timeout=180)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SPARKLE_EFFECTIVE_FLAGS checks=false allows=true downloads=true", result.stdout)
